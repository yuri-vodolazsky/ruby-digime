# frozen_string_literal: true

class Digime
  def initialize(contract_code, service_code)
    @logger = Logger.new(File.join(Rails.root, 'log/digime.log'))

    env = Rails.env || 'development'
    config = YAML.load_file(File.join(Rails.root, 'config/digime.yml'))[env]
    raise Digime::Error, 'Can not find config' unless config
    raise Digime::Error, "Can not find #{contract_code}'s contract details" unless config['contracts'][contract_code]
    raise Digime::Error, "Can not find #{service_code}'s service details" unless config['services'][service_code]

    @sdk_config = config['sdk']
    @service_id = config['services'][service_code]
    @contract_details = config['contracts'][contract_code]
    @contract_details['key'] = OpenSSL::PKey.read(File.read(File.join(Rails.root, "ssl/digime/#{@contract_details['key_file']}")))
    # key = OpenSSL::PKey.read(File.read(File.join(Rails.root, "ssl/digime/digi-me-example.key")))

    @logger.debug "Started with sdk_config: #{@sdk_config}, service_id: #{@service_id}, contract_details: #{@contract_details}"

    @jwt_encode_options = {
      'alg': 'PS512',
      'typ': 'JWT'
    }
    @callback_url = 'http://localhost:8081/error' # @todo: find better place for it (contract details config section?)
  end

  def get_authorize_url(user_id, redirect_url = nil)
    code_verifier = base64_url(alnum32)

    jwt_payload = {
      client_id: client_id,
      code_challenge: base64_url(hash_sha256(code_verifier)),
      code_challenge_method: 'S256',
      nonce: alnum32,
      redirect_uri: redirect_url || @contract_details['redirect_uri'],
      response_mode: 'query',
      response_type: 'code',
      state: "userId=#{user_id}",
      # timestamp: Time.now.to_i
      timestamp: timestamp_ms # milliseconds!
    }

    jwt_token = JWT.encode(jwt_payload, @contract_details['key'], 'PS512', @jwt_encode_options)

    @logger.debug "JWT payload: #{jwt_payload}"
    @logger.debug "JWT token: #{jwt_token}"

    headers = {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      'Authorization' => "Bearer #{jwt_token}"
    }
    response = HTTParty.post("#{@sdk_config['base_url']}oauth/authorize", headers: headers)

    @logger.debug "OAuth authorize response: #{response}"
    raise Digime::Error, "OAuth authorize responded with error code #{response.code}" if response.code != 201

    response_token = response['token']
    session = response['session']

    payload = JWT.decode(response_token, @contract_details['key'].public_key, nil, algorithm: 'PS512')
    preauthorization_code = payload.select { |item| item.keys.include?('preauthorization_code') }.first['preauthorization_code']

    authorize_url = "#{@sdk_config['onboard_url']}authorize?code=#{preauthorization_code}&callback=#{ERB::Util.url_encode(@callback_url)}&service=#{@service_id}"

    {
      authorize_url: authorize_url,
      code_verifier: code_verifier,
      session: session.deep_symbolize_keys
    }
  end

  def exchange_code_for_token(authorization_code, code_verifier, redirect_url = nil)
    jwt_payload = {
      client_id: client_id,
      code: authorization_code,
      code_verifier: code_verifier,
      grant_type: 'authorization_code',
      nonce: alnum32,
      redirect_uri: redirect_url || @contract_details['redirect_uri'],
      timestamp: timestamp_ms # milliseconds!
    }

    jwt_token = JWT.encode(jwt_payload, @contract_details['key'], 'PS512', @jwt_encode_options)

    @logger.debug "JWT payload: #{jwt_payload}"
    @logger.debug "JWT token: #{jwt_token}"

    headers = {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      'Authorization' => "Bearer #{jwt_token}"
    }
    response = HTTParty.post("#{@sdk_config['base_url']}oauth/token", headers: headers)

    @logger.debug "OAuth token response: #{response}"
    raise Digime::Error, "OAuth token responded with error code #{response.code}" if response.code != 200

    response_token = response['token']
    payload = JWT.decode(response_token, @contract_details['key'].public_key, nil, algorithm: 'PS512')
    tokens_payload = payload.select { |item| item.keys.include?('access_token') }.first

    {
      access_token: tokens_payload['access_token'].symbolize_keys,
      refresh_token: tokens_payload['refresh_token'].symbolize_keys
    }
  end

  # Get new session using access token
  def read_session(tokens)
    jwt_payload = {
      client_id: client_id,
      access_token: tokens[:access_token][:value],
      nonce: alnum32,
      redirect_uri: @contract_details['redirect_uri'],
      timestamp: timestamp_ms # milliseconds!
    }

    jwt_token = JWT.encode(jwt_payload, @contract_details['key'], 'PS512', @jwt_encode_options)

    @logger.debug "JWT payload: #{jwt_payload}"
    @logger.debug "JWT token: #{jwt_token}"

    headers = {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      'Authorization' => "Bearer #{jwt_token}"
    }
    response = HTTParty.post("#{@sdk_config['base_url']}permission-access/trigger", headers: headers)

    @logger.debug "Permission access response: #{response}"
    raise Digime::Error, "Permission access responded with error code #{response.code}" if response.code != 200

    JSON.parse(response.body).deep_symbolize_keys
  end

  def read_file_list(session_key)
    headers = {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json'
    }
    response = HTTParty.get("#{@sdk_config['base_url']}permission-access/query/#{session_key}", headers: headers)

    @logger.debug "Read file list response: #{response}"
    raise Digime::Error, "Read file list response status: #{response.code}, expected: completed" if response.code != 200

    JSON.parse(response.body).deep_symbolize_keys
  end

  def read_all_files(session_key)
    files = []
    state = 'pending'

    while state != 'partial' && state != 'completed'
      response = read_file_list(session_key)
      state = response[:status][:state]

      if state == 'pending'
        sleep 3
        next
      end

      files += response[:fileList].map do |file|
        read_file(session_key, file[:name])
      end

      if state == 'running'
        sleep 3
        next
      end
    end

    files
  end

  def read_file(session_key, file_name)
    file = fetch_file(session_key, file_name)
    decrypted_file = decrypt_file(file[:file_content])

    {
      file_data: JSON.parse(decrypted_file),
      file_metadata: file[:file_metadata],
      file_name: file_name
    }
  end

  def decrypt_file(file)
    file_size = file.size
    raise Digime::Error, 'File size is not valid' unless file_size >= 352 && file_size % 16 == 0

    dsk = @contract_details['key'].private_decrypt(file[0..255], OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    div = file[256..271]
    encrypted_hash_and_data = file[272..]

    decipher = OpenSSL::Cipher::AES.new(256, :CBC)
    decipher.decrypt
    decipher.key = dsk
    decipher.iv = div

    hash_and_data = decipher.update(encrypted_hash_and_data) + decipher.final
    hash = hash_and_data[0..63]
    data = hash_and_data[64..]
    raise Digime::Error, 'Hash is not valid' unless hash_sha512(data) == hash

    data
  end

  def fetch_file(session_key, file_name)
    headers = {
      'Accept' => 'application/octet-stream'
    }
    response = HTTParty.get("#{@sdk_config['base_url']}permission-access/query/#{session_key}/#{file_name}", headers: headers)

    raise Digime::Error, "Read file list response status: #{response.code}, expected: completed" if response.code != 200

    base64_meta = response.headers['x-metadata']
    decoded_meta = JSON.parse(Base64.urlsafe_decode64(base64_meta)).deep_symbolize_keys

    {
      compression: decoded_meta[:compression],
      file_metadata: decoded_meta[:metadata],
      file_content: response.body
    }
  end

  private

  def alnum32
    Digest::MD5.hexdigest(SecureRandom.base64)
  end

  def base64_url(str)
    Base64.urlsafe_encode64(str, padding: false)
  end

  def hash_sha256(str)
    hash_sha(OpenSSL::Digest::SHA256, str)
  end

  def hash_sha512(str)
    hash_sha(OpenSSL::Digest::SHA512, str)
  end

  def hash_sha(digest_class, str)
    sha = digest_class.new
    sha << str

    sha.digest
  end

  def timestamp_ms
    (Time.now.to_f * 1000).to_i
  end

  def client_id
    "#{@sdk_config['application_id']}_#{@contract_details['id']}"
  end
end
