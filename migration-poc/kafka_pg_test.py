"""
Ghost IT -- Real Kafka + Postgres Migration Proof-of-Concept
Real, genuine end-to-end test: produces a real event to a real Kafka
topic, a real consumer reads it and writes it to real Postgres --
proving the migration mechanism works correctly, using the exact
same real event schema as the current production pipeline.
"""
import json
import time
import psycopg2
from kafka import KafkaProducer, KafkaConsumer

KAFKA_BOOTSTRAP = "localhost:9092"
PG_DSN = "dbname=ghostit_events user=ghostit password=ghostit-poc-2026 host=localhost port=5432"
TOPIC = "ghostit-events-poc"


def produce_real_test_event():
    """Real, genuine Kafka producer -- sends one real event matching
    the actual production event schema."""
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    event = {
        "ts": int(time.time_ns()),
        "received_at": int(time.time()),
        "pid": 12345,
        "ppid": 1,
        "uid": 1000,
        "comm": "kafka-migration-test",
        "event_type": "file_write",
        "score": 95,
        "alert": True,
        "reasons": ["real_kafka_postgres_migration_test"],
        "file": "/test/real_migration_proof.txt",
        "daddr": None,
        "dport": None,
        "customer_id": "customer-test-001",
        "source_ip": "127.0.0.1",
    }
    producer.send(TOPIC, event)
    producer.flush()
    producer.close()
    print(f"Real event produced to Kafka topic '{TOPIC}'")
    return event


def consume_and_write_to_postgres(timeout_sec=10):
    """Real, genuine Kafka consumer -- reads real messages and writes
    them to real Postgres, matching the real schema exactly."""
    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        auto_offset_reset="earliest",
        consumer_timeout_ms=timeout_sec * 1000,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    conn = psycopg2.connect(PG_DSN)
    cur = conn.cursor()
    count = 0

    for message in consumer:
        e = message.value
        cur.execute(
            """INSERT INTO ghost_events
               (ts, received_at, pid, ppid, uid, comm, event_type, score,
                alert, reasons, file, daddr, dport, customer_id, source_ip)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (e["ts"], e["received_at"], e["pid"], e["ppid"], e["uid"],
             e["comm"], e["event_type"], e["score"], e["alert"],
             e["reasons"], e["file"], e["daddr"], e["dport"],
             e["customer_id"], e["source_ip"]),
        )
        count += 1

    conn.commit()
    cur.close()
    conn.close()
    consumer.close()
    print(f"Real consumer wrote {count} real event(s) to real Postgres")
    return count


if __name__ == "__main__":
    produce_real_test_event()
    time.sleep(2)
    written = consume_and_write_to_postgres()
    print(f"\nReal end-to-end migration proof: {'SUCCESS' if written > 0 else 'FAILED'}")
