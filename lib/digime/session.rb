# frozen_string_literal: true

class Digime::Session
  def self.get(user_id)
    key = get_key(user_id)
    data = get_node(key).get(key)
    data.nil? ? nil : JSON.parse(data).deep_symbolize_keys
  end

  def self.set(user_id, data)
    cache_ttl = 2_592_000 # 30 days
    key = get_key(user_id)
    get_node(key).setex(key, cache_ttl, data.to_json)
  end

  def self.get_key(user_id)
    "digime_user_session:#{user_id}"
  end

  def self.get_node(key)
    VorRedis.get_redis(key)
  end
end
