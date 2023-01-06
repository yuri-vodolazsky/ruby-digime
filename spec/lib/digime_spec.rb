# frozen_string_literal: true

RSpec.describe Digime, type: :lib do
  before(:each) do
    stub_everything
    @test_contract_code = 'spotify'
    @test_service_code = 'spotify'
  end

  describe '#alnum32' do
    it 'should return random alphanumeric string 32 characters long' do
      sdk = Digime.new(@test_contract_code, @test_service_code)
      alnum32 = sdk.send(:alnum32)

      expect(alnum32.size).to eq(32)
      expect(alnum32.match(/^[a-zA-Z0-9]+$/).nil?).to be_falsey
    end
  end

  describe '#base64_url' do
    it 'should perform base64 url encoding without padding' do
      alnum32 = 'gCABalxzPMpDasb0QbWyQhwXBeXnE4Rc'
      expected_base64encoded = 'Z0NBQmFseHpQTXBEYXNiMFFiV3lRaHdYQmVYbkU0UmM'

      sdk = Digime.new(@test_contract_code, @test_service_code)
      base64_encoded = sdk.send(:base64_url, alnum32)

      expect(base64_encoded).to eq(expected_base64encoded)
    end
  end

  describe '#hash_sha256' do
    it 'should produce expected hash' do
      str = 'WFY4VGFtWktsM2QwY2lWWVZ0T1o4OGE3WXhBdTVEQ2U'
      expected_hash_base64encoded = 'RmAaEdP8j_8MP1Wgryl5wQ56rji08hl6iX9C7Rn2gqM'

      sdk = Digime.new(@test_contract_code, @test_service_code)
      hash = sdk.send(:hash_sha256, str)
      hash_base64encoded = sdk.send(:base64_url, hash)

      expect(hash_base64encoded).to eq(expected_hash_base64encoded)
    end
  end

  describe '#hash_sha512' do
    it 'should produce expected hash' do
      str = 'His name was Gaal Dornick and he was just a country boy who had never seen Trantor before.'
      expected_hash_base64encoded = 'ZSqjK6-EZfcCBhql88fvW7Kimzuhj7uM_OiYdy50R2RrWSgg4cg4FO0GnOx5czC0DX2epmRPulf3Ka7bsgLWbg'

      sdk = Digime.new(@test_contract_code, @test_service_code)
      hash = sdk.send(:hash_sha512, str)
      hash_base64encoded = sdk.send(:base64_url, hash)

      expect(hash_base64encoded).to eq(expected_hash_base64encoded)
    end
  end

  describe '#decrypt_file' do
    xit 'should produce expected hash' do
      decrypted_file = File.read('spec/fixtures/files/digime/decrypted_file')
      encrypted_file = File.read('spec/fixtures/files/digime/encrypted_file')
      sdk = Digime.new(@test_contract_code, @test_service_code)
      file = sdk.decrypt_file(encrypted_file)
      expect(file).to eq(decrypted_file)
    end
  end
end
