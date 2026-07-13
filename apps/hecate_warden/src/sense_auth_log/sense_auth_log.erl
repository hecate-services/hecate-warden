%%% @doc The breadth sensor: read the host auth log, see every attacker.
%%%
%%% The tarpit catches the ones who probe our decoy ports; the real firehose is
%%% the box's actual sshd, taking tens of thousands of credential-spray attempts
%%% a day. We tail its log (mounted read-only from the host), count attempts per
%%% source IP in a rolling window, and when an IP crosses a threshold we publish
%%% a threat_sighted fact. That is what lets a general in one country warn the
%%% others: we measured a median 56-minute head start before the same attacker
%%% reaches the next box.
%%%
%%% Read-only. We parse log lines; we never touch sshd, and the warden cannot
%%% block anyone. It sees and it reports.
-module(sense_auth_log).
-include_lib("kernel/include/file.hrl").
-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).
-export([parse/1]).  %% exported for tests

%% A single fat-fingered login is not an attack. This many failures from one IP
%% inside the window is.
-define(THRESHOLD, 15).
-define(WINDOW_MS, 300000).      %% 5 minutes
-define(POLL_MS,   2000).
%% Don't re-report the same IP more often than this (it is still attacking).
-define(REPORT_COOLDOWN_MS, 600000).

-record(st, {path :: string(),
             fd :: file:io_device() | undefined,
             pos = 0 :: non_neg_integer(),
             %% ip => [timestamp_ms] within the window
             hits = #{} :: #{binary() => [integer()]},
             %% ip => last_reported_ms
             reported = #{} :: #{binary() => integer()},
             %% ip => set of usernames tried (evidence; revealing)
             users = #{} :: #{binary() => [binary()]}}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    Path = application:get_env(hecate_warden, auth_log, "/host/log/auth.log"),
    self() ! poll,
    {ok, #st{path = Path}}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info(poll, St) ->
    St2 = drain(open(St)),
    erlang:send_after(?POLL_MS, self(), poll),
    {noreply, St2};
handle_info(_Info, St) ->
    {noreply, St}.

terminate(_Reason, #st{fd = Fd}) ->
    _ = close(Fd),
    ok.

%% --- Internal ---

%% Open the log lazily, and reopen on rotation (size shrank below our position).
open(#st{fd = undefined, path = Path} = St) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, Fd} ->
            %% Start at end: we care about live attacks, not history.
            {ok, Eof} = file:position(Fd, eof),
            St#st{fd = Fd, pos = Eof};
        {error, _} ->
            St
    end;
open(#st{fd = Fd, path = Path, pos = Pos} = St) ->
    case file:read_file_info(Path) of
        {ok, #file_info{size = Size}} when Size < Pos ->
            _ = close(Fd),
            open(St#st{fd = undefined, pos = 0});
        _ ->
            St
    end.

close(undefined) -> ok;
close(Fd)        -> file:close(Fd).

drain(#st{fd = undefined} = St) ->
    St;
drain(#st{fd = Fd, pos = Pos} = St) ->
    case file:pread(Fd, Pos, 65536) of
        {ok, Data} ->
            St2 = lists:foldl(fun line/2, St, binary:split(Data, <<"\n">>, [global])),
            drain(St2#st{pos = Pos + byte_size(Data)});
        eof ->
            St;
        {error, _} ->
            St
    end.

%% A failed-auth line names a source IP (and often a username). Count it; when an
%% IP crosses the threshold in the window, report it once (then cool down).
line(Line, St) ->
    case parse(Line) of
        {ok, Ip, User} -> record(Ip, User, St);
        skip           -> St
    end.

parse(Line) ->
    Failed = binary:match(Line, <<"Failed password">>) =/= nomatch
             orelse binary:match(Line, <<"Invalid user">>) =/= nomatch
             orelse binary:match(Line, <<"authentication failure">>) =/= nomatch,
    parse(Failed, Line).

parse(false, _Line) ->
    skip;
parse(true, Line) ->
    case re:run(Line, <<"from ([0-9]{1,3}(?:\\.[0-9]{1,3}){3})">>,
                [{capture, [1], binary}]) of
        {match, [Ip]} -> {ok, Ip, user_of(Line)};
        nomatch       -> skip
    end.

user_of(Line) ->
    %% "Invalid user admin from ..." | "Failed password for root from ..." |
    %% "... user=root". Case-insensitive; the name runs to the next space.
    case re:run(Line, <<"(?:invalid user |user=|password for )([A-Za-z0-9._-]{1,32})">>,
                [caseless, {capture, [1], binary}]) of
        {match, [U]} -> U;
        nomatch      -> <<>>
    end.

record(Ip, User, St) ->
    Now = erlang:system_time(millisecond),
    Fresh = [T || T <- maps:get(Ip, St#st.hits, []), Now - T < ?WINDOW_MS],
    Hits = [Now | Fresh],
    Users = add_user(Ip, User, St#st.users),
    St2 = St#st{hits = maps:put(Ip, Hits, St#st.hits), users = Users},
    maybe_report(Ip, length(Hits), Now, St2).

add_user(_Ip, <<>>, Users) -> Users;
add_user(Ip, User, Users) ->
    Existing = maps:get(Ip, Users, []),
    case lists:member(User, Existing) of
        true  -> Users;
        false -> maps:put(Ip, lists:sublist([User | Existing], 20), Users)
    end.

maybe_report(Ip, Count, Now, St) when Count >= ?THRESHOLD ->
    Last = maps:get(Ip, St#st.reported, 0),
    report_if(Now - Last >= ?REPORT_COOLDOWN_MS, Ip, Count, Now, St);
maybe_report(_Ip, _Count, _Now, St) ->
    St.

report_if(false, _Ip, _Count, _Now, St) ->
    St;
report_if(true, Ip, Count, Now, St) ->
    _ = hecate_warden_facts:threat(#{source_ip => Ip,
                                     service => <<"ssh">>,
                                     attempts => Count,
                                     window_s => ?WINDOW_MS div 1000,
                                     usernames => maps:get(Ip, St#st.users, [])}),
    St#st{reported = maps:put(Ip, Now, St#st.reported)}.
