# -*- utf-8 -*-
require "sinatra"
require "sinatra/reloader"
require 'net/http'
require 'net/https'
require 'json'
require 'json/jwt'
require 'net/https'
require 'uri'

enable :sessions

#CLIENT_ID = "YOUR_CLIENT_ID"
#CLIENT_SECRET = "YOUR_CLIENT_SECRET"
CLIENT_ID = "573679233036-95tn2lfve36ahg6rkmli4ttnp50guu9g.apps.googleusercontent.com"
CLIENT_SECRET = "QDMoFyNdFn37sbzpGK-Un3wM"
REDIRECT_URI = "http://localhost:4567/oauth2callback"

module OpenIDConnect
  class Base
    attr_reader :client_id
    attr_reader :client_secret
    attr_reader :redirect_uri
    
    def initialize(client_id, client_secret, redirect_uri)
      @client_id = client_id
      @client_secret = client_secret
      @redirect_uri = redirect_uri
    end

    def nonce
      rand(36**6).to_s(36)
    end

    def verify_token(id_token, access_token, key, session, params)
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
      if jwt['iss'] != @issuer
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
    end
  end

  class Google < Base
    attr_reader :discovery
    attr_reader :jwks
    
    def initialize(client_id, client_secret, redirect_uri, options = {})
      super(client_id, client_secret, redirect_uri)

      fetch_discovery
      fetch_jwks

      @issuer = discovery['issuer']
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

    def authorization_endpoint
      @discovery['authorization_endpoint']
    end

    def token_endpoint
      @discovery['token_endpoint']
    end

  end
end

Auth = OpenIDConnect::Google.new(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)

get "/" do
  session[:state] = Auth.nonce
  session[:nonce] = Auth.nonce

  @authorization_code_uri = "#{Auth.authorization_endpoint}?scope=openid%20email%20profile&state=#{session[:state]}&redirect_uri=#{CGI::escape(Auth.redirect_uri)}&response_type=code&client_id=#{Auth.client_id}"

  @implicit_uri = "#{Auth.authorization_endpoint}?scope=openid%20email%20profile&state=#{session[:state]}&redirect_uri=#{CGI::escape(Auth.redirect_uri)}&response_type=id_token%20token&client_id=#{Auth.client_id}&nonce=#{session[:nonce]}"

  erb :index
end

get "/oauth2callback" do
  if params[:code]
    begin
      uri = URI.parse(Auth.token_endpoint)
      req = Net::HTTP::Post.new(uri.path)

      req.set_form_data(grant_type: 'authorization_code', code: params[:code], redirect_uri: Auth.redirect_uri, client_id: Auth.client_id, client_secret: Auth.client_secret)
      http = Net::HTTP.new(uri.host, uri.port)
      http.ca_file = "cacert.pem"
      http.use_ssl = true
      res = http.start {
        http.request(req)
      }

#      if params[:redirect_uri] != Auth.redirect_uri
#        raise "redirect_uri verification failed"
#      end

      json = JSON.parse(res.body)

      if json['error'] or res.code != '200'
        if json['error_description']
          raise json['error_description']
        else
          raise 'token verification failed'
        end
      else
        id_token = json['id_token']
        access_token = json['access_token']
        
        jwks = Auth.jwks
        jwt = JSON::JWT.decode(id_token, :skip_verification)
        kid = jwt.kid
        key = jwks[kid]
        
        Auth.verify_token(id_token, access_token, key, session, params)
        access_token
        return access_token
      end

    rescue JSON::JWS::VerificationFailed => e
      status 400
      return e.to_s
    rescue  => e
      status 400
      return e.to_s
    end
  end
  erb :oauth2callback
end

#
# catch id_token and verify
#
get "/catchtoken" do
  id_token = params[:id_token]
  access_token = params[:access_token]

  jwks = Auth.jwks
  jwt = JSON::JWT.decode(id_token, :skip_verification)
  kid = jwt.kid
  key = jwks[kid]

  begin
    Auth.verify_token(id_token, access_token, key, session, params)
    access_token
  rescue JSON::JWS::VerificationFailed => e
    status 400
    e.to_s
  rescue String => e
    status 400
    e.to_s
  end
end
