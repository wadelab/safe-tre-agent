import pandas as pd
import acro

# Both groups contain 10 rows, so both meet ACRO's default threshold.
df = pd.DataFrame({
    "group": ["sums to 10"] * 10 + ["sums to 0"] * 10,
    "value": [1.0] * 10 + [0.0] * 10,
})

acro.ACRO(suppress=False).crosstab(
    index=df["group"],
    columns=pd.Series("all", index=df.index),
    values=df["value"],
    aggfunc="sum",
)
