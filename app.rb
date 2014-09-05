# -*- utf-8 -*-
require "sinatra"
require "sinatra/reloader"
require 'net/http'
require 'net/https'
require 'json'
require 'json/jwt'
require 'net/https'
require 'uri'
require 'singleton'

enable :sessions

CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:4567/oauth2callback"

module OpenIDConnect
  class Google
    include Singleton

    attr_reader :discovery
    attr_reader :jwks
    
    def initialize
      fetch_discovery
      fetch_jwks
    end
    
    def fetch_discovery
      uri = URI.parse("https://accounts.google.com/.well-known/openid-configuration")
      http = Net::HTTP.new(uri.host, uri.port)
      http.ca_file = "cacert.pem"
      http.use_ssl = true
      res = http.start {
        http.get(uri.path)
      }
      
      @discovery = JSON.parse(res.body)
    end
    
    def fetch_jwks
      return @jwks if @jwks
      
      uri = URI.parse(@discovery['jwks_uri'])
      http = Net::HTTP.new(uri.host, uri.port)
      http.ca_file = "cacert.pem"
      http.use_ssl = true
      res = http.start {
        http.get(uri.path)
      }
      
      json = JSON.parse(res.body)
      
      jwks = {}
      json['keys'].each { |k|
        jwks[k['kid']] = JSON::JWK.decode(k)
      }
      @jwks = jwks
    end
  end
end

def nonce
  rand(36**6).to_s(36)
end

def verify_token(id_token, access_token, key)
  begin
    #verify state
    raise "state verification failed" if session[:state] != params[:state]
    
    #verify signature
    jwt = JSON::JWT.decode(id_token, key) 
    
    #verify hash alg
    if jwt.alg != 'RS256'
      raise JSON::JWS::VerificationFailed.new
    end
    
    #verify hash
    if jwt['at_hash'] != UrlSafeBase64.encode64(Digest::SHA256.digest(access_token)[0..15])
      raise "at_hash verification failed"
    end
    
    #verify nonce
    if jwt['nonce'] and jwt['nonce'] != session[:nonce]
      raise "nonce verification failed"
    end
    
    #verify iss
    if jwt['iss'] != OpenIDConnect::Google.instance.discovery['issuer']
      raise "iss verification failed"
    end
    
    #verify audience
    if jwt['aud'] != CLIENT_ID
      raise "aud verification failed"
    end
    
    #verify exp
    if Time.at(jwt['exp']) < Time.now
      raise "exp verification failed"
    end
    
    access_token
  rescue JSON::JWS::VerificationFailed => e
    status 400
    e.to_s
  rescue String => e
    status 400
    e.to_s
  end
end

get "/" do
  session[:state] = nonce
  session[:nonce] = nonce

  @authorization_code_uri = "#{OpenIDConnect::Google.instance.discovery['authorization_endpoint']}?scope=openid%20email%20profile&state=#{session[:state]}&redirect_uri=#{CGI::escape(REDIRECT_URI)}&response_type=code&client_id=#{CLIENT_ID}"

  @implicit_uri = "#{OpenIDConnect::Google.instance.discovery['authorization_endpoint']}?scope=openid%20email%20profile&state=#{session[:state]}&redirect_uri=#{CGI::escape(REDIRECT_URI)}&response_type=id_token%20token&client_id=#{CLIENT_ID}&nonce=#{session[:nonce]}"

  erb :index
end

get "/oauth2callback" do
  if params[:code]
    uri = URI.parse(OpenIDConnect::Google.instance.discovery['token_endpoint'])
    req = Net::HTTP::Post.new(uri.path)

    #req.basic_auth(CLIENT_ID, CLIENT_SECRET)

    req.set_form_data(grant_type: 'authorization_code', code: params[:code], redirect_uri: REDIRECT_URI, client_id: CLIENT_ID, client_secret: CLIENT_SECRET)
    http = Net::HTTP.new(uri.host, uri.port)
    http.ca_file = "cacert.pem"
    http.use_ssl = true
    res = http.start {
      http.request(req)
    }
    #puts res
    #puts res.body
    json = JSON.parse(res.body)

    id_token = json['id_token']
    access_token = json['access_token']

    jwks = OpenIDConnect::Google.instance.jwks
    jwt = JSON::JWT.decode(id_token, :skip_verification)
    kid = jwt.kid
    key = jwks[kid]

    verify_token(id_token, access_token, key)
  end
  erb :oauth2callback
end

#
# catch id_token and verify
#
get "/catchtoken" do
  id_token = params[:id_token]
  access_token = params[:access_token]

  jwks = OpenIDConnect::Google.instance.jwks
  jwt = JSON::JWT.decode(id_token, :skip_verification)
  kid = jwt.kid
  key = jwks[kid]

  verify_token(id_token, access_token, key)
end
