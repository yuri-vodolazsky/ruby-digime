# frozen_string_literal: true

class Api::V3::DigimeController < ApplicationController
  api :GET, '/v3/digime/get_authorize_url', 'Get authorize URL'
  param :service_code, String, 'Digi.me service code', required: true
  param :redirect_uri, String, 'Redirect URI (without proto and domain)', required: false
  error code: 422
  def get_authorize_url
    service_code = params[:service_code]
    redirect_url = params[:redirect_uri]
    redirect_url = MAILER_URL + redirect_url if redirect_url

    sdk = Digime.new(service_code, service_code)
    auth_resp = sdk.get_authorize_url(current_user.id.to_s, redirect_url)

    authorize_url = auth_resp.delete(:authorize_url)
    auth_resp[:redirect_url] = redirect_url
    Digime::Session.set(current_user.id, auth_resp)

    render json: { authorize_url: authorize_url }, status: :ok
  rescue Digime::Error => e
    render json: { errors: e.message }, status: :unprocessable_entity
  end

  api :GET, '/v3/digime/complete_auth', 'Complete auth with Digi.me'
  param :service_code, String, 'Digi.me service code', required: true
  param :authorization_code, String, 'Authorization code received from Digi.me', required: true
  error code: 422
  def complete_auth
    service_code = params[:service_code]
    authorization_code = params[:authorization_code]

    session = Digime::Session.get(current_user.id)
    raise Digime::Error, 'Session not found. Please call "get_authorize_url" endpoint first' unless session && session[:session] && session[:session][:key] && session[:code_verifier]

    sdk = Digime.new(service_code, service_code)
    tokens = sdk.exchange_code_for_token(authorization_code, session[:code_verifier], session[:redirect_url])

    session[:tokens] = tokens
    Digime::Session.set(current_user.id, session)

    render json: { status: 'ok' }, status: :ok
  rescue Digime::Error => e
    render json: { errors: e.message }, status: :unprocessable_entity
  end

  api :GET, '/v3/digime/get_all_files', 'Get all files'
  param :service_code, String, 'Digi.me service code', required: true
  error code: 422
  def get_all_files
    service_code = params[:service_code]

    session = Digime::Session.get(current_user.id)
    raise Digime::Error, 'Session not found. Please call "get_authorize_url" endpoint first' unless session && session[:session] && session[:session][:key]
    raise Digime::Error, 'Auth process is not completed. Please call "complete_auth" first' unless session[:tokens]

    sdk = Digime.new(service_code, service_code)
    files = sdk.read_all_files(session[:session][:key])

    render json: { files: files }, status: :ok
  rescue Digime::Error => e
    render json: { errors: e.message }, status: :unprocessable_entity
  end
end
