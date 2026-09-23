"""The blessed MonitorKit pin, in ONE place.

`run_matrix_scale.py`, `run_crossenv.py` and `sa_aggregate.py` import BLESSED_PIN; the bash runner
`run_matrix_ephem.sh` keeps its own copy (it cannot import Python). All four need the pin the campaign
runs and scores at, and they DRIFTED once already (D-109 advanced one script's default and left the
rest at the previous pin), silently mismatching the monitor a result claims to measure.

Why a LITERAL and not `git rev-parse HEAD:monitorkit`: the runner scripts operate against the shared
checkout (`PAPER`), whose `main` can lag `origin/main`, so a derived value would silently run the OLD
monitor. Instead this literal is the declared intent, and `tests/test_campaign_pin_literals.py` FAILS
if it drifts from the committed `monitorkit` gitlink (or if the bash copy drifts from here) — so
advancing the submodule without bumping this constant is caught in the gate, not three campaigns later.
Same duplicate-but-enforced idiom as matrix.RESAMPLABLE_CLASSES <-> runner._RETRIABLE_ABORT_CLASSES.

To advance the pin: set this to the new full 40-hex `monitorkit` gitlink AND run_matrix_ephem.sh's
EXPECT_PIN default to its first 12 hex; the test tells you if you missed one.
"""
BLESSED_PIN = "ae2957dd3874013f538adf9b87154ccd54c7910b"
