%% 2013-2014 (c) Mega Yu <yuhg2310@gmail.com>
%% 2013-2014 (c) huaban.com <www.huaban.com>
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%    http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
-module(erlzk_conn).
-behaviour(gen_server).

-include("erlzk.hrl").
-include_lib("kernel/include/inet.hrl").

-export([start/3, start/4, start_link/3, start_link/4, stop/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export([create/5, delete/3, exists/3, exists/4, get_data/3, get_data/4, set_data/4, get_acl/2, set_acl/4,
         get_children/3, get_children/4, sync/2, get_children2/3, get_children2/4,
         multi/2, create2/5, add_auth/3, no_heartbeat/1,
         kill_session/1, block_incoming_data/1, unblock_incoming_data/1]).

-define(ZK_SOCKET_OPTS, [binary, {active, once}, {packet, 4}, {reuseaddr, true}, {linger, {false, 0}}]).
-define(ZK_SOCKET_OPTS_CLOSE, [{linger, {true, 1}}]).
-ifdef(zk_connect_timeout).
-define(ZK_CONNECT_TIMEOUT, ?zk_connect_timeout).
-else.
-define(ZK_CONNECT_TIMEOUT, 10000).
-endif.
-ifdef(zk_reconnect_interval).
-define(ZK_RECONNECT_INTERVAL, ?zk_reconnect_interval).
-else.
-define(ZK_RECONNECT_INTERVAL, 1000).
-endif.
-ifdef(pre18).
-define(RANDOM_UNIFORM, random:uniform()).
-else.
-define(RANDOM_UNIFORM, rand:uniform()).
-endif.

-record(state, {
    servers = [],
    auth_data = [],
    chroot = "/",
    socket,
    host,
    port,
    proto_ver = 0,
    timeout,
    session_id = 0,
    password = <<0:128>>,
    ping_interval = infinity,
    xid = 1,
    zxid = 0,
    reset_watch = true,
    reconnect_expired = true,
    monitor,
    heartbeat_watcher,
    reqs = dict:new(),
    auths = queue:new(),
    watchers = {dict:new(), dict:new(), dict:new()}
}).

%% ===================================================================
%% Public API
%% ===================================================================
start(ServerList, Timeout, Options) ->
    gen_server:start(?MODULE, [ServerList, Timeout, Options], []).

start(ServerName, ServerList, Timeout, Options) ->
    gen_server:start(ServerName, ?MODULE, [ServerList, Timeout, Options], []).

start_link(ServerList, Timeout, Options) ->
    gen_server:start_link(?MODULE, [ServerList, Timeout, Options], []).

start_link(ServerName, ServerList, Timeout, Options) ->
    gen_server:start_link(ServerName, ?MODULE, [ServerList, Timeout, Options], []).

stop(Pid) ->
    gen_server:call(Pid, stop, infinity).

create(Pid, Path, Data, Acl, CreateMode) ->
    gen_server:call(Pid, {create, {Path, Data, Acl, CreateMode}}, infinity).

delete(Pid, Path, Version) ->
    gen_server:call(Pid, {delete, {Path, Version}}, infinity).

exists(Pid, Path, Watch) ->
    gen_server:call(Pid, {exists, {Path, Watch}}, infinity).

exists(Pid, Path, Watch, Watcher) ->
    gen_server:call(Pid, {exists, {Path, Watch}, Watcher}, infinity).

get_data(Pid, Path, Watch) ->
    gen_server:call(Pid, {get_data, {Path, Watch}}, infinity).

get_data(Pid, Path, Watch, Watcher) ->
    gen_server:call(Pid, {get_data, {Path, Watch}, Watcher}, infinity).

set_data(Pid, Path, Data, Version) ->
    gen_server:call(Pid, {set_data, {Path, Data, Version}}, infinity).

get_acl(Pid, Path) ->
    gen_server:call(Pid, {get_acl, {Path}}, infinity).

set_acl(Pid, Path, Acl, Version) ->
    gen_server:call(Pid, {set_acl, {Path, Acl, Version}}, infinity).

get_children(Pid, Path, Watch) ->
    gen_server:call(Pid, {get_children, {Path, Watch}}, infinity).

get_children(Pid, Path, Watch, Watcher) ->
    gen_server:call(Pid, {get_children, {Path, Watch}, Watcher}, infinity).

sync(Pid, Path) ->
    gen_server:call(Pid, {sync, {Path}}, infinity).

get_children2(Pid, Path, Watch) ->
    gen_server:call(Pid, {get_children2, {Path, Watch}}, infinity).

get_children2(Pid, Path, Watch, Watcher) ->
    gen_server:call(Pid, {get_children2, {Path, Watch}, Watcher}, infinity).

multi(Pid, Ops) ->
    gen_server:call(Pid, {multi, Ops}, infinity).

create2(Pid, Path, Data, Acl, CreateMode) ->
    gen_server:call(Pid, {create2, {Path, Data, Acl, CreateMode}}, infinity).

add_auth(Pid, Scheme, Auth) ->
    gen_server:call(Pid, {add_auth, {Scheme, Auth}}, infinity).

no_heartbeat(Pid) ->
    gen_server:cast(Pid, no_heartbeat).

kill_session(Pid) ->
    gen_server:call(Pid, kill_session, infinity).

block_incoming_data(Pid) ->
    gen_server:cast(Pid, block_incoming_data).

unblock_incoming_data(Pid) ->
    gen_server:cast(Pid, unblock_incoming_data).

%% ===================================================================
%% gen_server Callbacks
%% ===================================================================
init([ServerList, Timeout, Options]) ->
    State = connect(#state{servers = ServerList,
                           auth_data = proplists:get_value(auth_data, Options, []),
                           chroot = get_chroot_path(proplists:get_value(chroot, Options, "/")),
                           timeout = Timeout,
                           reset_watch = not proplists:get_bool(disable_watch_auto_reset, Options),
                           reconnect_expired = not proplists:get_bool(disable_expire_reconnect, Options),
                           monitor = proplists:get_value(monitor, Options)
                          }),
    {ok, State, State#state.ping_interval}.

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_, _From, State=#state{socket=undefined}) ->
    {reply, {error, closed}, State};
handle_call({add_auth, Args}, From, State=#state{socket=Socket, ping_interval=PingIntv, auths=Auths}) ->
    case gen_tcp:send(Socket, erlzk_codec:pack(add_auth, Args, -4)) of
        ok ->
            NewAuths = queue:in({From, Args}, Auths),
            {noreply, State#state{auths=NewAuths}, PingIntv};
        {error, Reason} ->
            {reply, {error, Reason}, State, PingIntv}
    end;
handle_call({Op, Args}, From, State=#state{chroot=Chroot, socket=Socket, xid=Xid, ping_interval=PingIntv, reqs=Reqs}) ->
    case gen_tcp:send(Socket, erlzk_codec:pack(Op, Args, Xid, Chroot)) of
        ok ->
            NewReqs = dict:store(Xid, {Op, From}, Reqs),
            {noreply, State#state{xid=Xid+1, reqs=NewReqs}, PingIntv};
        {error, Reason} ->
            {reply, {error, Reason}, State#state{xid=Xid+1}, PingIntv}
    end;
handle_call({Op, Args, Watcher}, From, State=#state{chroot=Chroot, socket=Socket, xid=Xid, ping_interval=PingIntv, reqs=Reqs}) ->
    case gen_tcp:send(Socket, erlzk_codec:pack(Op, Args, Xid, Chroot)) of
        ok ->
            Path = element(1, Args),
            NewReqs = dict:store(Xid, {Op, From, Path, Watcher}, Reqs),
            {noreply, State#state{xid=Xid+1, reqs=NewReqs}, PingIntv};
        {error, Reason} ->
            {reply, {error, Reason}, State#state{xid=Xid+1}, PingIntv}
    end;
handle_call(kill_session, _From, State=#state{ping_interval=PingIntv}) ->
    % create a second connection for this zk session then close it - this is the approved
    % way to make a zk session timeout.
    case connect(State#state{socket = undefined,
                             host = undefined,
                             port = undefined,
                             monitor = undefined,
                             heartbeat_watcher = undefined,
                             reqs = dict:new(),
                             auths = queue:new()
                            }) of
        #state{socket = undefined} ->
            {reply, {error, connect_failed}, State, PingIntv};
        SecondState ->
            disconnect(SecondState, true),
            {reply, ok, State, PingIntv}
    end;
handle_call(_Request, _From, State=#state{ping_interval=PingIntv}) ->
    {noreply, State, PingIntv}.

handle_cast(no_heartbeat, State=#state{host=Host, port=Port}) ->
    error_logger:error_msg("Connection to ~p:~p is not responding, will close and reconnect~n", [Host, Port]),
    NewState = sync_reconnect(State),
    {noreply, NewState, NewState#state.ping_interval};
handle_cast(block_incoming_data, State=#state{socket=Socket, ping_interval=PingIntv}) ->
    %% block incoming data by setting the socket to passive mode
    inet:setopts(Socket, [{active, false}]),
    {noreply, State, PingIntv};
handle_cast(unblock_incoming_data, State=#state{socket=Socket, ping_interval=PingIntv}) ->
    %% return the socket to active mode
    inet:setopts(Socket, [{active, once}]),
    {noreply, State, PingIntv};
handle_cast(_Request, State=#state{ping_interval=PingIntv}) ->
    {noreply, State, PingIntv}.

handle_info(timeout, State=#state{socket=undefined}) ->
    {noreply, State};
handle_info(timeout, State=#state{socket=Socket, ping_interval=PingIntv}) ->
    gen_tcp:send(Socket, <<-2:32, 11:32>>),
    {noreply, State, PingIntv};
handle_info({tcp, Socket, Packet}, State=#state{chroot=Chroot, socket=Socket, ping_interval=PingIntv,
                                               auths=Auths, auth_data=AuthData, reqs=Reqs, watchers=Watchers,
                                               heartbeat_watcher={HeartbeatWatcher, _HeartbeatRef}}) ->
    inet:setopts(Socket, [{active, once}]),
    {Xid, Zxid, Code, Body} = erlzk_codec:unpack(Packet),
    erlzk_heartbeat:beat(HeartbeatWatcher),
    case Xid of
        -1 -> % watched event
            {EventType, _KeeperState, PathList} = erlzk_codec:unpack(watched_event, Body, Chroot),
            Path = list_to_binary(PathList),
            {Receivers, NewWatchers} = find_and_erase_watchers(EventType, Path, Watchers),
            send_watched_event(Receivers, Path, EventType),
            {noreply, State#state{zxid=Zxid, watchers=NewWatchers}, PingIntv};
        -2 -> % ping
            {noreply, State#state{zxid=Zxid}, PingIntv};
        -8 -> % set watches
            case Code of
                ok -> {noreply, State#state{zxid=Zxid}, PingIntv};
                _  -> {noreply, State#state{zxid=Zxid, watchers={dict:new(), dict:new(), dict:new()}}, PingIntv}
            end;
        -4 -> % auth
            NewAuthData =
                case queue:out(Auths) of
                    {{value, init_auth}, NewAuths} ->
                        AuthData;
                    {{value, {From, Auth}}, NewAuths} when Code =:= ok ->
                        gen_server:reply(From, ok),
                        [Auth | AuthData];
                    {{value, {From, _Auth}}, NewAuths} ->
                        gen_server:reply(From, {error, Code}),
                        AuthData;
                    {empty, NewAuths} ->
                        error_logger:info_msg("Unexpected auth reply from ~p:~p (ignored)~n",
                                              [State#state.host, State#state.port]),
                        AuthData
                end,
            {noreply, State#state{zxid=Zxid, auths=NewAuths, auth_data=NewAuthData}, PingIntv};
        _  -> % normal reply
            case dict:find(Xid, Reqs) of
                {ok, Req} ->
                    {Op, From} = case Req of
                        {X, Y}       -> {X, Y};
                        {X, Y, _, _} -> {X, Y}
                    end,
                    NewReqs = dict:erase(Xid, Reqs),
                    Reply = get_reply_from_body(Code, Op, Body, Chroot),
                    NewWatchers = maybe_store_watcher(Code, Req, Watchers),
                    gen_server:reply(From, Reply),
                    {noreply, State#state{zxid=Zxid, reqs=NewReqs, watchers=NewWatchers}, PingIntv};
                error ->
                    {noreply, State#state{zxid=Zxid}, PingIntv}
            end
    end;
handle_info({tcp_closed, Socket}, State=#state{socket=Socket, host=Host, port=Port}) ->
    error_logger:error_msg("Connection to ~p:~p is broken, reconnecting now~n", [Host, Port]),
    NewState = sync_reconnect(State),
    {noreply, NewState, NewState#state.ping_interval};
handle_info({tcp_error, Socket, Reason}, State=#state{socket=Socket, host=Host, port=Port}) ->
    error_logger:error_msg("Connection to ~p:~p encountered an error, will close and reconnect: ~p~n", [Host, Port, Reason]),
    NewState = sync_reconnect(State),
    {noreply, NewState, NewState#state.ping_interval};
handle_info(reconnect, State) ->
    NewState = connect(State),
    {noreply, NewState, NewState#state.ping_interval};
handle_info({'DOWN', Ref, process, Pid, Reason}, State=#state{heartbeat_watcher={Pid, Ref}}) ->
    error_logger:warning_msg("Heartbeat process exit: ~p~n", [Reason]),
    NewState = start_heartbeat(State),
    {noreply, NewState, NewState#state.ping_interval};
handle_info({'DOWN', _Ref, process, _Pid, _Reason}, State=#state{ping_interval=PingIntv}) ->
    {noreply, State, PingIntv};
handle_info(_Info, State=#state{ping_interval=PingIntv}) ->
    {noreply, State, PingIntv}.

terminate(Reason, State) ->
    disconnect(State, true),
    case Reason of
        normal   -> error_logger:info_msg("Server is closed~n");
        shutdown -> error_logger:info_msg("Server is shutting down~n");
        _        -> error_logger:error_msg("Server is terminated: ~p~n", [Reason])
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ===================================================================
%% Internal Functions
%% ===================================================================

shuffle(L) ->
    % Uses rand module rather than random when available, so initial seed is not constant and list is shuffled differently on first call
    [X||{_,X} <- lists:sort([{?RANDOM_UNIFORM, N} || N <- L])].

sync_reconnect(State) ->
    connect(disconnect(State)).

disconnect(State) ->
    disconnect(State, false).

disconnect(State=#state{socket = undefined}, _CloseSession) ->
    %% Already disconnected
    State;
disconnect(State=#state{session_id = SessionId,
                        socket = Socket,
                        host = Host,
                        port = Port,
                        heartbeat_watcher = {HBPid, HBMon},
                        monitor = Monitor,
                        reqs = Reqs,
                        auths = Auths
                       },
           CloseSession) ->
    %% Close the connection (and the session too, when necessary)
    NewSessionId =
        if CloseSession ->
                inet:setopts(Socket, ?ZK_SOCKET_OPTS_CLOSE),
                gen_tcp:send(Socket, <<1:32, -11:32>>),
                <<0:128>>;
           true ->
                SessionId
        end,
    gen_tcp:close(Socket),
    %% Stop heartbeat
    demonitor(HBMon, [flush]),
    erlzk_heartbeat:stop(HBPid),
    %% Notify monitor and pending requests
    notify_monitor_server_state(Monitor, disconnected, Host, Port),
    lists:foreach(fun notify_req_closed/1, dict:to_list(Reqs)),
    lists:foreach(fun notify_auth_closed/1, queue:to_list(Auths)),
    %% Clear state
    State#state{session_id = NewSessionId,
                socket = undefined,
                host = undefined,
                port = undefined,
                heartbeat_watcher = undefined,
                reqs = dict:new(),
                auths = queue:new(),
                ping_interval = infinity
               }.

notify_req_closed({_Xid, {_Op, From}}) ->
    gen_server:reply(From, {error, closed});
notify_req_closed({_Xid, {_Op, From, _Path, _Watcher}}) ->
    gen_server:reply(From, {error, closed}).

notify_auth_closed(init_auth) ->
    ok;
notify_auth_closed({From, _Auth}) ->
    gen_server:reply(From, {error, closed}).

connect(State=#state{socket = Socket}) when Socket =/= undefined ->
    %% Already connected
    State;
connect(State=#state{servers = Servers}) ->
    %% Resolve the server names to IP addresses upon every reconnect
    %% attempt. This way we can handle both round-robin DNS names and
    %% DNS name changes.
    ResolvedServers = [{Address, Port}
                       || {Host, Port} <- Servers,
                          Address <- case inet:gethostbyname(Host) of
                                         {ok, #hostent{h_addr_list = Addresses}} -> Addresses;
                                         {error, Reason} ->
                                             error_logger:error_msg("Resolving ~p:~p encountered an error: ~p~n",
                                                                    [Host, Port, Reason]),
                                             []
                                     end
                      ],
    case connect(shuffle(ResolvedServers), State) of
        {error, Retry} ->
            %% Maybe try again later
            if Retry -> erlang:send_after(?ZK_RECONNECT_INTERVAL, self(), reconnect);
               true -> ok
            end,
            State;
        {ok, NewState = #state{host = Host, port = Port, monitor = Monitor}} ->
            %% Notify monitor
            notify_monitor_server_state(Monitor, connected, Host, Port),
            %% Restore session state
            reset_watch(add_init_auths(start_heartbeat(NewState)))
    end.

connect([], _State) ->
    {error, true};
connect([{Host, Port} | Rest] = Servers, State = #state{reconnect_expired = ReconnectExpired, monitor = Monitor}) ->
    case connect(Host, Port, State) of
        {ok, _NewState} = Res -> Res;
        {error, session_expired} when ReconnectExpired ->
            error_logger:warning_msg("Session expired, reconnecting with a fresh session~n"),
            notify_monitor_server_state(Monitor, expired, Host, Port),
            connect(Servers, State#state{session_id = 0,
                                         password = <<0:128>>,
                                         proto_ver = 0,
                                         xid = 1});
        {error, session_expired} ->
            error_logger:warning_msg("Session expired, will not reconnect"),
            {error, false};
        {error, _Other} ->
            connect(Rest, State)
    end.

connect(Host, Port,
        State = #state{proto_ver = ProtocolVersion,
                       zxid = Zxid,
                       timeout = Timeout,
                       session_id = SessionId,
                       password = Password
                      }) ->
    error_logger:info_msg("Connecting to ~p:~p~n", [Host, Port]),
    case gen_tcp:connect(Host, Port, ?ZK_SOCKET_OPTS, ?ZK_CONNECT_TIMEOUT) of
        {ok, Socket} ->
            error_logger:info_msg("Connected ~p:~p, sending connect command~n", [Host, Port]),
            ConnectMsg = erlzk_codec:pack(connect, {ProtocolVersion, Zxid, Timeout, SessionId, Password}),
            case gen_tcp:send(Socket, ConnectMsg) of
                ok ->
                    receive
                        {tcp, Socket, Packet} ->
                            inet:setopts(Socket, [{active, once}]),
                            {NewProtocolVersion, NewTimeout, NewSessionId, NewPassword} =
                                erlzk_codec:unpack(connect, Packet),
                            case NewSessionId of
                                0 ->
                                    gen_tcp:close(Socket),
                                    {error, session_expired};
                                _ ->
                                    error_logger:info_msg("Connection to ~p:~p is established~n", [Host, Port]),
                                    {ok, State#state{socket = Socket,
                                                     host = Host,
                                                     port = Port,
                                                     proto_ver = NewProtocolVersion,
                                                     timeout = NewTimeout,
                                                     session_id = NewSessionId,
                                                     password = NewPassword,
                                                     ping_interval = NewTimeout div 3
                                                    }}
                            end;
                        {tcp_closed, Socket} ->
                            error_logger:error_msg("Connection to ~p:~p is closed~n", [Host, Port]),
                            {error, tcp_closed};
                        {tcp_error, Socket, Reason} ->
                            error_logger:error_msg("Connection to ~p:~p encountered an error: ~p~n",
                                                   [Host, Port, Reason]),
                            gen_tcp:close(Socket),
                            {error, tcp_error}
                    after ?ZK_CONNECT_TIMEOUT ->
                            error_logger:error_msg("Connection to ~p:~p timeout~n", [Host, Port]),
                            gen_tcp:close(Socket),
                            {error, timeout}
                    end;
                {error, Reason} ->
                    error_logger:error_msg("Sending connect command to ~p:~p encountered an error: ~p~n",
                                           [Host, Port, Reason]),
                    gen_tcp:close(Socket),
                    {error, tcp_send}
            end;
        {error, Reason} ->
            error_logger:error_msg("Connecting to ~p:~p encountered an error: ~p~n", [Host, Port, Reason]),
            {error, tcp_connect}
    end.

add_init_auths(State=#state{auth_data=AuthData, auths=Auths, socket=Socket, host=Host, port=Port}) ->
    NewAuths = lists:foldl(
                 fun (Args, Queue) ->
                         case gen_tcp:send(Socket, erlzk_codec:pack(add_auth, Args, -4)) of
                             ok ->
                                 queue:in(init_auth, Queue);
                             {error, Reason} ->
                                 error_logger:error_msg("Error sending an init auth to ~p:~p (~p)~n",
                                                        [Host, Port, Reason]),
                                 Queue
                         end
                 end,
                 Auths,
                 AuthData),
    State#state{auths=NewAuths}.

reset_watch(State=#state{reset_watch = ResetWatch, watchers={DataWatchers, ExistWatchers, ChildWatchers}, zxid=Zxid,
                         socket=Socket, host=Host, port=Port}) ->
    case ResetWatch andalso
        not (dict:is_empty(DataWatchers) andalso
             dict:is_empty(ExistWatchers) andalso
             dict:is_empty(ChildWatchers)) of
        true ->
            Args = {Zxid, dict:fetch_keys(DataWatchers), dict:fetch_keys(ExistWatchers), dict:fetch_keys(ChildWatchers)},
            case gen_tcp:send(Socket, erlzk_codec:pack(set_watches, Args, -8)) of
                ok ->
                    State;
                {error, Reason} ->
                    error_logger:error_msg("Error resetting watches to ~p:~p (~p)~n",
                                           [Host, Port, Reason]),
                    State#state{watchers={dict:new(), dict:new(), dict:new()}}
            end;
        false ->
            State#state{watchers={dict:new(), dict:new(), dict:new()}}
    end.

notify_monitor_server_state(Monitor, State, Host, Port) ->
    case Monitor of
        undefined ->
            ok;
        _ ->
            Monitor ! {State, Host, Port}
    end.

should_add_watcher(no_node, exists) -> true;
should_add_watcher(ok, _Op)         -> true;
should_add_watcher(_Code, _Op)      -> false.

maybe_store_watcher(_Code, {_Op, _From}, Watchers) ->
    Watchers;
maybe_store_watcher(Code, {Op, _From, Path, Watcher}, Watchers) ->
    case should_add_watcher(Code, Op) of
        false -> Watchers;
        true -> store_watcher(Op, Path, Watcher, Watchers)
    end.

store_watcher(Op, Path, Watcher, Watchers) when not is_binary(Path)->
    store_watcher(Op, iolist_to_binary(Path), Watcher, Watchers);
store_watcher(Op, Path, Watcher, Watchers) ->
    {Index, DestWatcher} = get_watchers_by_op(Op, Watchers),
    NewWatchers = dict:append(Path, Watcher, DestWatcher),
    setelement(Index, Watchers, NewWatchers).

get_watchers_by_op(Op, {DataWatchers, ExistWatchers, ChildWatchers}) ->
    case Op of
        get_data      -> {1, DataWatchers};
        exists        -> {2, ExistWatchers};
        get_children  -> {3, ChildWatchers};
        get_children2 -> {3, ChildWatchers};
        _             -> {1, DataWatchers} % just in case, shouldn't be here
    end.

find_and_erase_watchers(node_created, Path, Watchers) ->
    find_and_erase_watchers([exists], Path, Watchers);
find_and_erase_watchers(node_deleted, Path, Watchers) ->
    find_and_erase_watchers([get_data, exists, get_children], Path, Watchers);
find_and_erase_watchers(node_data_changed, Path, Watchers) ->
    find_and_erase_watchers([get_data, exists], Path, Watchers);
find_and_erase_watchers(node_children_changed, Path, Watchers) ->
    find_and_erase_watchers([get_children], Path, Watchers);
find_and_erase_watchers(Ops, Path, Watchers) ->
    find_and_erase_watchers(Ops, Path, Watchers, sets:new()).

find_and_erase_watchers([], _Path, Watchers, Receivers) ->
    {sets:to_list(Receivers), Watchers};
find_and_erase_watchers([Op|Left], Path, Watchers, Receivers) ->
    {Index, DestWatcher} = get_watchers_by_op(Op, Watchers),
    R = case dict:find(Path, DestWatcher) of
        {ok, X} -> sets:union(sets:from_list(X), Receivers);
        error   -> Receivers
    end,
    NewWatchers = dict:erase(Path, DestWatcher),
    W = setelement(Index, Watchers, NewWatchers),
    find_and_erase_watchers(Left, Path, W, R).

send_watched_event([], _Path, _EventType) ->
    ok;
send_watched_event([Watcher|Left], Path, EventType) ->
    Watcher ! {EventType, Path},
    send_watched_event(Left, Path, EventType).

get_chroot_path(P) when is_binary(P) ->
    get_chroot_path(unicode:characters_to_list(P));
get_chroot_path(P) when is_list(P) ->
    case string:strip(P, right, $/) of
        "" -> "/";
        Path -> Path
    end.

get_reply_from_body(ok, _Op, <<>>, _Chroot) -> ok;
get_reply_from_body(ok, Op, Body, Chroot) ->
    Result = erlzk_codec:unpack(Op, Body, Chroot),
    multi_result(Op, Result);
get_reply_from_body(no_node, _Op, _Body, _Chroot) -> {error, no_node};
get_reply_from_body(Code, _, _, _) -> {error, Code}.

multi_result(multi, {ok, _}=Result) -> Result;
multi_result(multi, Result)         -> {error, Result};
multi_result(_, Result)             -> {ok, Result}.

start_heartbeat(State = #state{timeout=Timeout}) ->
    {ok, Pid} = erlzk_heartbeat:start(self(), Timeout * 2 div 3),
    State#state{heartbeat_watcher = {Pid, erlang:monitor(process, Pid)}}.
