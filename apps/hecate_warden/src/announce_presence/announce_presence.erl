%%% @doc The warden announces itself to the mesh on a heartbeat, so the
%%% federation map builds its sensor roster LIVE — no hard-coded box list.
%%%
%%% A box appears the moment it boots (not only when it first sees an attack),
%%% and drops off when its heartbeat goes stale. A third-party warden dropping
%%% into the commons self-registers on the map with no change on our side.
%%%
%%% Publishes `warden/presence' every ?INTERVAL_MS via hecate_warden_facts.
%%% Degrades silently while the mesh is dark (the publish is a no-op then).
-module(announce_presence).
-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Heartbeat cadence. The map's freshness window must be a comfortable multiple
%% of this so a single missed beat does not blink a box offline.
-define(INTERVAL_MS, 60000).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

init([]) ->
    %% Announce once at boot, then on every tick.
    self() ! announce,
    {ok, #{}}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info(announce, St) ->
    _ = hecate_warden_facts:presence(),
    erlang:send_after(?INTERVAL_MS, self(), announce),
    {noreply, St};
handle_info(_Msg, St) ->
    {noreply, St}.

terminate(_Reason, _St) -> ok.
