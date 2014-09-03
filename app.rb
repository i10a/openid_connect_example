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

authorization = OpenIDConnect::Google.instance

get "/" do
  session[:state] = nonce
  session[:nonce] = nonce

  @implicit_url = "#{authorization.discovery['authorization_endpoint']}?scope=email%20profile&state=#{session[:state]}&redirect_uri=#{CGI::escape(REDIRECT_URI)}&response_type=id_token%20token&client_id=#{CLIENT_ID}&nonce=#{session[:nonce]}"

  erb :index
end

get "/oauth2callback" do
  erb :oauth2callback
end

#
# catch id_token and verify
#
get "/catchtoken" do
  id_token = params[:id_token]
  access_token = params[:access_token]

  jwks = authorization.jwks
  jwt = JSON::JWT.decode(id_token, :skip_verification)
  kid = jwt.kid

  begin
    #verify state
    raise "state verification failed" if session[:state] != params[:state]

    #verify signature
    jwt = JSON::JWT.decode(id_token, jwks[kid]) 

    #verify hash alg
    if jwt.alg != 'RS256'
      raise JSON::JWS::VerificationFailed.new
    end

    #verify hash
    if jwt['at_hash'] != UrlSafeBase64.encode64(Digest::SHA256.digest(access_token)[0..15])
      raise "at_hash verification failed"
    end

    #verify nonce
    if jwt['nonce'] != session[:nonce]
      raise "nonce verification failed"
    end

    #verify iss
    if jwt['iss'] != authorization.discovery['issuer']
      raise "iss verification failed"
    end

    jwt.to_s
  rescue JSON::JWS::VerificationFailed => e
    status 400
    e.to_s
  rescue String => e
    status 400
    e.to_s
  end
end

