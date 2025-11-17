from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable
import json
import logging
import os
import time
import atexit
from datetime import datetime

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_USER_EVENTS_TOPIC = os.getenv("KAFKA_USER_EVENTS_TOPIC", "user-events")

MAX_RETRIES = 10
RETRY_DELAY = 3
BOOTSTRAP_SERVERS = "localhost:29092"


def utc_iso():
    return datetime.utcnow().isoformat()


class KafkaProducerService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize_producer()
        return cls._instance

    def _initialize_producer(self):
        retries = 0

        while retries < MAX_RETRIES:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(","),
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    key_serializer=lambda k: str(k).encode("utf-8") if k else None,
                    retries=5,
                    max_in_flight_requests_per_connection=1,
                    acks="all",
                    request_timeout_ms=30000,
                    retry_backoff_ms=1000,
                )

                logger.info(f"✅ Kafka producer connected: {KAFKA_BOOTSTRAP_SERVERS}")
                return

            except NoBrokersAvailable:
                retries += 1
                logger.warning(
                    f"⏳ Kafka unavailable (attempt {retries}/{MAX_RETRIES}). "
                    f"Retrying in {RETRY_DELAY}s..."
                )
                time.sleep(RETRY_DELAY)
            except Exception as e:
                logger.error(f"❌ Kafka init error: {e}")
                break

        logger.error("❌ Failed to initialize Kafka producer after retries.")
        self.producer = None

    def is_healthy(self):
        return self.producer is not None

    def _send_event(self, event_type: str, payload: dict, key=None):
        if not self.producer:
            logger.error("❌ Kafka producer not initialized.")
            return False

        event = {
            "event_type": event_type,
            "timestamp": utc_iso(),
            "service": "user-service",
            "data": payload,
        }

        try:
            future = self.producer.send(
                KAFKA_USER_EVENTS_TOPIC,
                value=event,
                key=key,
            )

            future.add_errback(lambda exc: logger.error(f"Kafka delivery failed: {exc}"))

            logger.info(f"📤 Sent event '{event_type}' (key={key})")
            return True

        except KafkaError as e:
            logger.error(f"❌ Kafka error sending '{event_type}': {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected Kafka send error: {e}")
            return False

    def flush(self):
        if self.producer:
            self.producer.flush()

    def close(self):
        if self.producer:
            self.producer.close()
            logger.info("🔌 Kafka producer closed")


producer_instance = KafkaProducerService()
atexit.register(producer_instance.close)

def send_user_registered(user):
    return producer_instance._send_event(
        "user_registered",
        {
            "id": user.id,
            "email": user.email,
            "username": getattr(user, "username", None),
            "moti_id": getattr(user, "moti_id", None),
            "role": getattr(user, "role", None),
            "is_active": user.is_active,
            "date_joined": utc_iso(),
        },
        key=user.id,
    )


def send_user_updated(user, changed_fields=None):
    return producer_instance._send_event(
        "user_updated",
        {
            "id": user.id,
            "email": user.email,
            "username": getattr(user, "username", None),
            "changed_fields": changed_fields or [],
            "updated_at": utc_iso(),
        },
        key=user.id,
    )


def send_user_login(user, login_method="email"):
    return producer_instance._send_event(
        "user_logged_in",
        {
            "id": user.id,
            "email": user.email,
            "login_method": login_method,
            "login_time": utc_iso(),
        },
        key=user.id,
    )


def send_user_deleted(user_id, email=None):
    return producer_instance._send_event(
        "user_deleted",
        {
            "id": user_id,
            "email": email,
            "deleted_at": utc_iso(),
        },
        key=user_id,
    )
