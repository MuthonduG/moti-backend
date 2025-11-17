import json
import logging
from kafka import KafkaConsumer
import os
from django.conf import settings

logger = logging.getLogger(__name__)

class UserEventsConsumer:
    def __init__(self):
        self.bootstrap_servers = os.getenv('KAFKA_BOOTSTRAP_SERVERS', 'kafka:9092')
        self.topic = os.getenv('KAFKA_USER_EVENTS_TOPIC', 'user-events')
        self.group_id = os.getenv('KAFKA_CONSUMER_GROUP_ID', 'journey-service-group')
        self.consumer = None
        
    def start_consuming(self):
        try:
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='earliest',
                enable_auto_commit=True,
                auto_commit_interval_ms=5000
            )
            
            logger.info(f"🎯 Journey service started consuming from topic: {self.topic}")
            
            for message in self.consumer:
                self.process_message(message)
                
        except Exception as e:
            logger.error(f"❌ Error in Kafka consumer: {e}")
        finally:
            if self.consumer:
                self.consumer.close()
    
    def process_message(self, message):
        try:
            event_data = message.value
            event_type = event_data.get('event_type')
            user_data = event_data.get('data', {})
            
            logger.info(f"📥 Received event: {event_type} for user {user_data.get('id')}")
            
            if event_type == 'user_registered':
                self.handle_user_registered(user_data)
            elif event_type == 'user_logged_in':
                self.handle_user_login(user_data)
            elif event_type == 'user_updated':
                self.handle_user_updated(user_data)
            elif event_type == 'user_deleted':
                self.handle_user_deleted(user_data)
            else:
                logger.warning(f"⚠️ Unknown event type: {event_type}")
                
        except Exception as e:
            logger.error(f"❌ Error processing message: {e}")
    
    def handle_user_registered(self, user_data):
        try:
            from .models import UserJourney  
            
            user_id = user_data.get('id')
            email = user_data.get('email')
            
            journey, created = UserJourney.objects.get_or_create(
                user_id=user_id,
                defaults={
                    'email': email,
                    'current_stage': 'onboarding',
                    'total_logins': 0
                }
            )
            
            if created:
                logger.info(f"🚀 Created journey for new user: {email}")
            else:
                logger.info(f"📝 Updated journey for existing user: {email}")
                
        except Exception as e:
            logger.error(f"❌ Error handling user registration: {e}")
    
    def handle_user_login(self, user_data):
        try:
            from .models import UserJourney
            
            user_id = user_data.get('id')
            login_method = user_data.get('login_method', 'unknown')
            
            journey, created = UserJourney.objects.get_or_create(
                user_id=user_id,
                defaults={
                    'email': user_data.get('email'),
                    'current_stage': 'active',
                    'total_logins': 1,
                    'last_login_method': login_method
                }
            )
            
            if not created:
                journey.total_logins += 1
                journey.last_login_method = login_method
                journey.save()
                logger.info(f"🔐 Updated login count for user {user_id}: {journey.total_logins}")
                
        except Exception as e:
            logger.error(f"❌ Error handling user login: {e}")
    
    def handle_user_updated(self, user_data):
        try:
            from .models import UserJourney
            
            user_id = user_data.get('id')
            changed_fields = user_data.get('changed_fields', [])
            
            if 'email' in changed_fields:
                journey = UserJourney.objects.filter(user_id=user_id).first()
                if journey:
                    journey.email = user_data.get('email')
                    journey.save()
                    logger.info(f"✉️ Updated email in journey for user {user_id}")
                    
        except Exception as e:
            logger.error(f"❌ Error handling user update: {e}")
    
    def handle_user_deleted(self, user_data):
        try:
            from .models import UserJourney
            
            user_id = user_data.get('id')
            
            deleted_count, _ = UserJourney.objects.filter(user_id=user_id).delete()
            
            if deleted_count > 0:
                logger.info(f"🗑️ Deleted journey for user {user_id}")
            else:
                logger.info(f"ℹ️ No journey found to delete for user {user_id}")
                
        except Exception as e:
            logger.error(f"❌ Error handling user deletion: {e}")

user_events_consumer = UserEventsConsumer()
