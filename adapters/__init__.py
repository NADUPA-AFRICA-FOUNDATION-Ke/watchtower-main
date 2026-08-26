"""Collectors for scheduled mode.

Sweep sources (`core/sources.py`) answer "what is being said about X right
now?" — they take a keyword and are stateless. These answer "what is new since
last time?" — they take a *place to watch* and are stateful, which is the whole
difference: every one of them consults `store.is_seen()` so a run that finds
nothing new is cheap rather than a re-fetch of yesterday's page.

Every collector returns `list[Item]` and never raises for an ordinary failure.
That is deliberate and it is the opposite of the sweep's rule. A sweep is a
question a person just asked and is waiting on, so a source that could not be
searched has to say so loudly. A scheduled run is unattended: one dead feed at
03:00 must not stop the other eleven from collecting. Failures are recorded in
`item.raw_meta` and on the returned `errors` list of each module instead.
"""

from . import gdelt, rss, social, webpage

__all__ = ["gdelt", "rss", "social", "webpage"]
