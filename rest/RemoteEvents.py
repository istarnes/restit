"""
REDIS + WebSockets = WS4REDIS

"""
import json
from django.conf import settings

try:
	from ws4redis.redis_store import RedisMessage
	from ws4redis.publisher import RedisPublisher, getRedisClient
	from ws4redis.redis_store import RedisStore, SELF
except:
	pass


def buildEventMessage(name, message=None, priority=0, component=None, component_id=None, custom=None):
	msg = {
		"name":name,
		"priority":priority
	}
	if message:
		msg["message"] = message

	if component:
		msg["component"] = {
			"id": component_id,
			"model": component
		}

	if custom:
		msg.update(custom)

	return json.dumps(msg)

def get(key, default=None):
	c = getRedisClient()
	v = c.get(key)
	if v is None:
		return default
	return v

def set(key, value):
	c = getRedisClient()
	return c.set(key, value)

def incr(key, amount=1):
	c = getRedisClient()
	return c.incr(key, amount)

def decr(key, amount=1):
	c = getRedisClient()
	return c.decr(key, amount)

def delete(key):
	c = getRedisClient()
	return c.delete(key)

## SET FUNCTIONS
def sadd(name, *values):
	# add value to set
	c = getRedisClient()
	return c.sadd(name, *values)

def srem(name, *values):
	# remove value from set
	c = getRedisClient()
	return c.srem(name, *values)

def sismember(name, value):
	# return items in set
	c = getRedisClient()
	return c.sismember(name, value)

def scard(name):
	# count items in set
	c = getRedisClient()
	return c.scard(name)

def smembers(name):
	# return items in set
	c = getRedisClient()
	return c.smembers(name)

## HASH FUNCTIONS

def hget(name, field, default=None):
	c = getRedisClient()
	v = c.hget(name, field)
	if v is None:
		return default
	return v

def hgetall(name):
	c = getRedisClient()
	return c.hgetall(name)	

def hset(name, field, value):
	c = getRedisClient()
	return c.hset(name, field, value)

def hdel(name, field):
	c = getRedisClient()
	return c.hdel(name, field)

def hincrby(name, field, inc=1):
	c = getRedisClient()
	return c.hincrby(name, field, inc)	


def sendToUser(user, name, message=None, priority=0, component=None, component_id=None, custom=None):
    return sendMessageToUsers([user], buildEventMessage(name, message, priority, component, component_id, custom))

def sendToUsers(users, name, message=None, priority=0, component=None, component_id=None, custom=None):
	return sendMessageToUsers(users, buildEventMessage(name, message, priority, component, component_id, custom))

def sendMessageToUsers(users, msg):
	return RedisPublisher(facility="events", users=users).publish_message(RedisMessage(msg))


def sendToGroup(group, name, message=None, priority=0, component=None, component_id=None, custom=None):
    return sendMessageToGroups([group], buildEventMessage(name, message, priority, component, component_id, custom))

def sendToGroups(groups, name, message=None, priority=0, component=None, component_id=None, custom=None):
	return sendMessageToGroups(groups, buildEventMessage(name, message, priority, component, component_id, custom))

def sendMessageToGroups(groups, msg):
	return RedisPublisher(facility="events", groups=groups).publish_message(RedisMessage(msg))


def sendToTerminal(terminal, name, message=None, priority=0, component=None, component_id=None, custom=None):
    return sendMessageToTerminal(terminal, buildEventMessage(name, message, priority, component, component_id, custom))

# def sendToTerminals(terminals, name, message=None, priority=0, component=None, component_id=None, custom=None):
# 	return sendMessageToTerminals(terminals, buildEventMessage(name, message, priority, component, component_id, custom))

def sendMessageToTerminal(terminal, msg):
	return RedisPublisher(facility="events", terminals=terminal).publish_message(RedisMessage(msg))


def broadcast(name, message=None, priority=0, component=None, component_id=None, custom=None):
	return broadcastMessage(buildEventMessage(name, message, priority, component, component_id, custom))

def broadcastMessage(msg):
	return RedisPublisher(facility="events", broadcast=True).publish_message(RedisMessage(msg))


