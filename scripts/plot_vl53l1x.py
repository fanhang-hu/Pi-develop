#!/usr/bin/env python3
import argparse
import re
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
import pandas as pd

BASE_STYLE = {
    "linestyle": "solid",
    "marker": "o",
    "markersize": 3,
    "linewidth": 1.2,
}

SERIES_STYLE = {
    "v1": {**BASE_STYLE, "color": "#359d81", "marker": "o"},
    "v2": {**BASE_STYLE, "color": "#ceaf7e", "marker": "v"},
    "bias": {**BASE_STYLE, "color": "#444444", "marker": "s"},
}


def apply_style():
    mpl.rcParams["font.family"] = "DejaVu Sans"
    mpl.rcParams["font.size"] = 11
    plt.rcParams["xtick.direction"] = "in"
    plt.rcParams["ytick.direction"] = "in"


def downsample(df, step):
    if step <= 1:
        return df
    return df.iloc[::step].reset_index(drop=True)


def marker_indices(times, interval_s):
    if interval_s <= 0 or len(times) == 0:
        return list(range(len(times)))
    indices = []
    next_t = float(times.iloc[0])
    for i, t in enumerate(times):
        if float(t) + 1e-9 >= next_t:
            indices.append(i)
            next_t += interval_s
    return indices


def parse_gateway_log(path: Path):
    pattern = re.compile(r"\[gateway\] send seq=(\d+) v2=([0-9.]+)")
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = pattern.search(line)
            if not m:
                continue
            seq = int(m.group(1))
            val = float(m.group(2))
            rows.append({"seq": seq, "v2_value": val})
    return pd.DataFrame(rows)


def plot_series(df, xkey, ykey, title, out_path: Path, ylabel, style_key="v1", marker_interval_s=5.0):
    fig, ax = plt.subplots(figsize=(5.2, 2.6))
    style = SERIES_STYLE.get(style_key, BASE_STYLE)
    line_style = {**style, "marker": None}
    ax.plot(df[xkey], df[ykey], **line_style)
    idx = marker_indices(df[xkey], marker_interval_s)
    ax.plot(df[xkey].iloc[idx], df[ykey].iloc[idx], linestyle="None", **style)
    ax.set_title(title)
    ax.set_xlabel("Time (s)" if xkey == "t_monotonic_s" else xkey)
    ax.set_ylabel(ylabel)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def plot_combined(series_list, title, out_path: Path, marker_interval_s=5.0):
    fig, ax = plt.subplots(figsize=(5.2, 2.6))
    for series in series_list:
        style = SERIES_STYLE.get(series["style"], BASE_STYLE)
        line_style = {**style, "marker": None}
        ax.plot(
            series["x"],
            series["y"],
            label=series["label"],
            **line_style,
        )
        idx = marker_indices(series["x"], marker_interval_s)
        ax.plot(
            series["x"].iloc[idx],
            series["y"].iloc[idx],
            linestyle="None",
            label="_nolegend_",
            **style,
        )
    ax.set_title(title)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Value")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(out_path, dpi=300)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Plot v1/v2/bias data (template style)")
    parser.add_argument("--v1", required=True, help="Path to v1.csv")
    parser.add_argument("--v2", required=True, help="Path to v2.csv")
    parser.add_argument("--gateway-log", help="Path to gateway.log (for bias plot)")
    parser.add_argument("--out-dir", default=".", help="Output directory for images")
    parser.add_argument("--downsample", type=int, default=10, help="Downsample step for line (default 10)")
    parser.add_argument(
        "--marker-interval-s",
        type=float,
        default=5.0,
        help="Marker interval in seconds (default 5.0)",
    )
    parser.add_argument("--title-prefix", default="VL53L1X", help="Title prefix")
    parser.add_argument(
        "--combine",
        action="store_true",
        help="Also output a single combined figure (v1/v2/bias) if available",
    )
    args = parser.parse_args()

    apply_style()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    v1_df = pd.read_csv(args.v1)
    v2_df = pd.read_csv(args.v2)

    v1_df = downsample(v1_df, args.downsample)
    v2_df = downsample(v2_df, args.downsample)

    plot_series(
        v1_df,
        "t_monotonic_s",
        "distance_mm",
        f"{args.title_prefix} v1 (raw)",
        out_dir / "v1.png",
        "Distance (mm)",
        style_key="v1",
        marker_interval_s=args.marker_interval_s,
    )

    plot_series(
        v2_df,
        "t_monotonic_s",
        "v2_value",
        f"{args.title_prefix} v2 (linear)",
        out_dir / "v2.png",
        "v2 value",
        style_key="v2",
        marker_interval_s=args.marker_interval_s,
    )

    combined_series = [
        {
            "x": v1_df["t_monotonic_s"],
            "y": v1_df["distance_mm"],
            "label": "v1 (raw)",
            "style": "v1",
        },
        {
            "x": v2_df["t_monotonic_s"],
            "y": v2_df["v2_value"],
            "label": "v2 (linear)",
            "style": "v2",
        },
    ]

    if args.gateway_log:
        bias_df = parse_gateway_log(Path(args.gateway_log))
        if not bias_df.empty:
            bias_df = bias_df.merge(
                v2_df[["seq", "t_monotonic_s"]], on="seq", how="left"
            )
            if bias_df["t_monotonic_s"].isna().all():
                bias_df["t_monotonic_s"] = bias_df["seq"].astype(float)
                xkey = "t_monotonic_s"
            else:
                xkey = "t_monotonic_s"
            bias_df = downsample(bias_df, args.downsample)
            plot_series(
                bias_df,
                xkey,
                "v2_value",
                f"{args.title_prefix} v2 (bias attack)",
                out_dir / "v2_bias.png",
                "v2 value",
                style_key="bias",
                marker_interval_s=args.marker_interval_s,
            )
            if xkey == "t_monotonic_s":
                combined_series.append(
                    {
                        "x": bias_df["t_monotonic_s"],
                        "y": bias_df["v2_value"],
                        "label": "v2 (bias)",
                        "style": "bias",
                    }
                )

    if args.combine:
        plot_combined(
            combined_series,
            f"{args.title_prefix} v1/v2/bias",
            out_dir / "v1_v2_bias.png",
            marker_interval_s=args.marker_interval_s,
        )


if __name__ == "__main__":
    main()
