%%% @doc Top supervisor for hecate_warden.
%%%
%%% Two children, one per sense/act surface. Each owns its own work; there is no
%%% central "manager". The auth-log sensor tails real attacks; the tarpit listens
%%% on decoy ports and holds attackers. Both publish to the mesh directly.
-module(hecate_warden_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    SupFlags = #{strategy => one_for_one, intensity => 5, period => 10},
    Children = [
        %% Reads the host auth log, detects credential-spray, publishes
        %% threat_sighted facts. Breadth: every attacker on the real sshd.
        worker(sense_auth_log),

        %% Binds the decoy ports and holds every connection open, dribbling a
        %% slow fake SSH banner. Depth: the ones who took the bait. Publishes
        %% attacker_ensnared facts. BEAM holds tens of thousands of these idle
        %% connections for the cost of a socket and a timer each.
        worker(tarpit_listener)
    ],
    {ok, {SupFlags, Children}}.

worker(Module) ->
    #{id => Module,
      start => {Module, start_link, []},
      restart => permanent,
      shutdown => 5000,
      type => worker,
      modules => [Module]}.
