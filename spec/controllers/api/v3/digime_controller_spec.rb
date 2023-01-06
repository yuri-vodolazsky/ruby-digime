# frozen_string_literal: true

require 'spec_helper'

describe ::Api::V3::DigimeController do
  before(:each) do
    stub_everything

    @user = FactoryGirl.create(:user)
    session[:user_id] = @user.id
    session[:guid] = @user.idp_id

    @authorize_url = 'https://example.com/login_page'
    @code_verifier = 'YjRlOTFkZGQ0MmI1MDlkMGUyYTUzMjIxMmMxOTc4NDY'
    @session_key = 'cyomxHajR2ZR6PEmOeV58XXNqNqfAqrR'
    @digime_session = {
      expiry: (1.hour.from_now.to_f * 1000).to_i,
      key: @session_key
    }

    @get_authorize_url_mock_response = {
      authorize_url: @authorize_url,
      code_verifier: @code_verifier,
      session: @digime_session
    }

    @authorization_code = '149545a279f56b36a004f00aa67f...'
    @tokens = {
      access_token: {
        expires_on: (1.hour.from_now.to_f * 1000).to_i,
        value: '641cbe920aad25020a9...'
      },
      refresh_token: {
        expires_on: (6.months.from_now.to_f * 1000).to_i,
        value: '48b7338d71fb2c4255f...'
      }
    }

    @file = {
      file_data: 'Decrypted file data',
      file_metadata: {},
      file_name: 'file_1_0_1.json'
    }
  end

  describe 'GET #get_authorize_url' do
    it 'not allow to start auth process for non authorized doit user' do
      session[:user_id] = nil
      session[:guid] = nil

      get :get_authorize_url, service_code: 'spotify'
      expect(response.code.to_i).to eq(401)
      json_body = JSON.parse(response.body)
      expect(json_body['errors']).to eq('Not Authenticated')
    end
    it 'return authorization URL if success' do
      allow_any_instance_of(Digime).to receive(:get_authorize_url).and_return(@get_authorize_url_mock_response)
      get :get_authorize_url, service_code: 'spotify'
      expect(response.code.to_i).to eq(200)
      json_body = JSON.parse(response.body)
      expect(json_body['authorize_url']).to eq(@authorize_url)
    end
  end

  describe 'GET #complete_auth' do
    it 'return error if Digi.me session not found for the user' do
      get :complete_auth, service_code: 'spotify', authorization_code: @authorization_code
      expect(response.code.to_i).to eq(422)
      json_body = JSON.parse(response.body)
      expect(json_body['errors']).to eq('Session not found. Please call "get_authorize_url" endpoint first')
    end
    it 'return ok if success' do
      Digime::Session.set(@user.id, code_verifier: @code_verifier, session: @digime_session)
      allow_any_instance_of(Digime).to receive(:exchange_code_for_token).and_return(@tokens)
      get :complete_auth, service_code: 'spotify', authorization_code: @authorization_code
      expect(response.code.to_i).to eq(200)
      json_body = JSON.parse(response.body)
      expect(json_body['status']).to eq('ok')
      expect(Digime::Session.get(@user.id)[:tokens]).to be_truthy # Tokens should be written in user session
    end
  end

  describe 'GET #get_all_files' do
    it 'return error if Digi.me session not found for the user' do
      get :get_all_files, service_code: 'spotify'
      expect(response.code.to_i).to eq(422)
      json_body = JSON.parse(response.body)
      expect(json_body['errors']).to eq('Session not found. Please call "get_authorize_url" endpoint first')
    end
    it 'return error if Digi.me auth process has not been finished' do
      Digime::Session.set(@user.id, code_verifier: @code_verifier, session: @digime_session)
      get :get_all_files, service_code: 'spotify'
      expect(response.code.to_i).to eq(422)
      json_body = JSON.parse(response.body)
      expect(json_body['errors']).to eq('Auth process is not completed. Please call "complete_auth" first')
    end
    it 'return ok if success' do
      Digime::Session.set(@user.id, code_verifier: @code_verifier, session: @digime_session, tokens: @tokens)
      allow_any_instance_of(Digime).to receive(:read_all_files).and_return([@file])
      get :get_all_files, service_code: 'spotify'
      expect(response.code.to_i).to eq(200)
      json_body = JSON.parse(response.body)
      expect(json_body['files']).to be_truthy
    end
  end
end
