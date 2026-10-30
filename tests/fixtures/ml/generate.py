"""Write the tiny synthetic ML fixture datasets in this directory.

The files have the datasets' file names and headers but made-up values. The CIC-IDS-2017
header is copied from the release; the UNSW-NB15 header follows the published feature list and
is to be checked against the real files once they are downloaded. The rows are
chosen to exercise every cleaning rule: duplicates that differ only in identifiers,
feature-identical rows with different classes, rows shared between the official training and
testing files, "Attempted" flows, infinite and missing values, a class with a single row and a
category value never seen in training. Deterministic; re-run after changing it:

    uv run python tests/fixtures/ml/generate.py
"""

import csv
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The headers exactly as published, one string each so they can be compared by eye.
UNSW_COLUMNS = (  # noqa: SIM905
    "id,dur,proto,service,state,spkts,dpkts,sbytes,dbytes,rate,sttl,dttl,sload,dload,sloss,"
    "dloss,sinpkt,dinpkt,sjit,djit,swin,stcpb,dtcpb,dwin,tcprtt,synack,ackdat,smean,dmean,"
    "trans_depth,response_body_len,ct_srv_src,ct_state_ttl,ct_dst_ltm,ct_src_dport_ltm,"
    "ct_dst_sport_ltm,ct_dst_src_ltm,is_ftp_login,ct_ftp_cmd,ct_flw_http_mthd,ct_src_ltm,"
    "ct_srv_dst,is_sm_ips_ports,attack_cat,label"
).split(",")

CICIDS_COLUMNS = (  # noqa: SIM905
    "id,Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,"
    "Total Fwd Packet,Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,"
    "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
    "Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,"
    "Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,"
    "Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,"
    "Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,"
    "Bwd URG Flags,Fwd RST Flags,Bwd RST Flags,Fwd Header Length,Bwd Header Length,"
    "Fwd Packets/s,Bwd Packets/s,Packet Length Min,Packet Length Max,Packet Length Mean,"
    "Packet Length Std,Packet Length Variance,FIN Flag Count,SYN Flag Count,RST Flag Count,"
    "PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,Down/Up Ratio,"
    "Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,Fwd Bytes/Bulk Avg,"
    "Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,"
    "Bwd Bulk Rate Avg,Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,"
    "Subflow Bwd Bytes,FWD Init Win Bytes,Bwd Init Win Bytes,Fwd Act Data Pkts,"
    "Fwd Seg Size Min,Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,"
    "Idle Min,ICMP Code,ICMP Type,Total TCP Flow Time,Label,Attempted Category"
).split(",")

UNSW_TEXT = {"proto", "service", "state", "attack_cat"}
CICIDS_FIXED = {
    "id",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Label",
    "Attempted Category",
}


def _unsw_row(rng: random.Random, category: str) -> dict[str, object]:
    row: dict[str, object] = {c: rng.randint(0, 9999) for c in UNSW_COLUMNS if c not in UNSW_TEXT}
    row["dur"] = round(rng.uniform(0, 5), 6)
    row["proto"] = rng.choice(["tcp", "udp"])
    row["service"] = rng.choice(["-", "http", "dns"])
    row["state"] = rng.choice(["FIN", "INT", "CON"])
    row["attack_cat"] = category
    row["label"] = 0 if category == "Normal" else 1
    return row


def unsw(rng: random.Random) -> None:
    folder = HERE / "unsw-nb15"
    folder.mkdir(exist_ok=True)
    classes = ["Normal"] * 20 + ["Exploits"] * 8 + ["DoS"] * 6 + ["Generic"] * 4 + ["Worms"]
    train = [_unsw_row(rng, c) for c in classes]
    train += [dict(train[i]) for i in (0, 1, 21)]  # exact duplicates (new ids below)
    conflict = dict(train[2])
    conflict.update(attack_cat="Exploits", label=1)  # same features, other class
    train.append(conflict)
    test = [_unsw_row(rng, c) for c in ["Normal"] * 6 + ["Exploits"] * 3 + ["DoS"] * 2]
    test += [dict(train[3]), dict(train[22])]  # also in the training file
    test[0]["proto"] = "sctp"  # never seen in training
    test[1]["service"] = ""  # missing value
    for rows, name in ((train, "training"), (test, "testing")):
        for number, row in enumerate(rows, 1):
            row["id"] = number
        _write(folder / f"UNSW_NB15_{name}-set.csv", UNSW_COLUMNS, rows)


def _cicids_row(rng: random.Random, number: int, label: str, attempted: int) -> dict[str, object]:
    row: dict[str, object] = {
        c: rng.randint(0, 99999) for c in CICIDS_COLUMNS if c not in CICIDS_FIXED
    }
    row["Flow Packets/s"] = round(rng.uniform(0, 1000), 6)
    source, target = f"192.0.2.{number % 250 + 1}", "198.51.100.7"
    port, dport, protocol = rng.randint(1024, 65535), rng.choice([22, 80, 443]), 6
    row.update(
        {
            "id": number,
            "Flow ID": f"{source}-{target}-{port}-{dport}-{protocol}",
            "Src IP": source,
            "Src Port": port,
            "Dst IP": target,
            "Dst Port": dport,
            "Protocol": protocol,
            "Timestamp": f"2017-07-03 09:{number % 60:02d}:00.000000",
            "Label": label,
            "Attempted Category": attempted,
        }
    )
    return row


def cicids(rng: random.Random) -> None:
    folder = HERE / "cicids2017"
    folder.mkdir(exist_ok=True)
    days: dict[str, list[tuple[str, int]]] = {
        "monday": [("BENIGN", -1)] * 12,
        "tuesday": [("BENIGN", -1)] * 6 + [("FTP-Patator", -1)] * 4 + [("SSH-Patator", -1)] * 3,
        "wednesday": [("BENIGN", -1)] * 6
        + [("DoS Hulk", -1)] * 5
        + [("DoS Hulk - Attempted", 0)] * 2
        + [("Heartbleed", -1)],
        "thursday": [("BENIGN", -1)] * 5
        + [("Web Attack - Brute Force", -1)] * 3
        + [("Infiltration - Portscan", -1)] * 3,
        "friday": [("BENIGN", -1)] * 6 + [("Portscan", -1)] * 5 + [("DDoS", -1)] * 4,
    }
    number = 0
    first: dict[str, object] = {}
    for day, labels in days.items():
        rows = []
        for label, attempted in labels:
            number += 1
            rows.append(_cicids_row(rng, number, label, attempted))
        if day == "monday":
            first = rows[0]
        else:
            # The same flow again on another day: only identifiers and time differ.
            again = dict(first)
            number += 1
            again.update(id=number, Timestamp="2017-07-04 10:00:00.000000", **{"Src Port": 50000})
            rows.append(again)
        if day == "wednesday":
            rows[0]["Flow Bytes/s"] = "Infinity"
            rows[1]["Flow Bytes/s"] = ""
            rows[2]["Flow IAT Min"] = "not-a-number"
        _write(folder / f"{day}.csv", CICIDS_COLUMNS, rows)


def _write(path: Path, columns: list[str], rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    unsw(random.Random(14))  # noqa: S311 - made-up fixture values
    cicids(random.Random(2017))  # noqa: S311


if __name__ == "__main__":
    main()
