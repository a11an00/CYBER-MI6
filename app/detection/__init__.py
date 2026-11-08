"""Detection rules and the engine that runs them.

Every rule module exposes the same small interface (see web_paths.py, the reference):

    RULE_NAME                                   the ``rule`` stored on alerts
    evaluate(event, recent_events, settings)    -> AlertIn | None   (pure: no DB, no clock)
    history_query(event, settings)              -> dict | list[dict] | None   (optional)

``history_query`` tells the engine which earlier events the rule needs, as keyword
arguments for ``storage.events_in_window``. Rules without history (web_paths,
dns_anomaly) simply don't define it.
"""
