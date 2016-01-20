module Rack
  module OAuth2
    class Server

      # Access token. This is what clients use to access resources.
      #
      # An access token is a unique code, associated with a client, an identity
      # and scope. It may be revoked, or expire after a certain period.
      class AccessToken
        include DataMapper::Resource

        class << self

          # Find AccessToken from token. Does not return revoked tokens.
          def from_token(token)
            get(token)
          end

          # Get an access token (create new one if necessary).
          #
          # You can set optional expiration in seconds. If zero or nil, token
          # never expires.
          def get_token_for(identity, client, scope, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity
            scope = Utils.normalize_scope(scope) & (client ? client.scope : [])

            token = first(:expires_at => nil, :expires_at.gt => Time.now,
              :identity => identity, :scope => scope, :client => client,
              :revoked => nil)

            unless token
              return create_token_for(client, scope, identity, expires)
            end
            token
          end

          # Creates a new AccessToken for the given client and scope.
          def create_token_for(client, scope, identity = nil, expires = nil)
            expires_at = Time.now.to_i + expires if expires && expires != 0
            token = { :scope=>scope, :client=>client,
                      :expires_at=>expires_at, :revoked=>nil }
            token[:identity] = identity if identity
            c = self.create(token)
            c
          end

          # Find all AccessTokens for an identity.
          def from_identity(identity)
            all(:identity => identity)
          end

          # Returns all access tokens for a given client, Use limit and offset
          # to return a subset of tokens, sorted by creation date.
          def for_client(client_id, offset = 0, limit = 100)
            all(:client => client, :order => [ :created_at.asc ], :limit => limit)
          end

          # Returns count of access tokens.
          #
          # @param [Hash] filter Count only a subset of access tokens
          # @option filter [Integer] days Only count that many days (since now)
          # @option filter [Boolean] revoked Only count revoked (true) or non-revoked (false) tokens; count all tokens if nil
          # @option filter [String, ObjectId] client_id Only tokens grant to this client
          def count(filter = {})
            select = {}
            if filter[:days]
              now = Time.now.to_i
              range = { :$gt=>now - filter[:days] * 86400, :$lte=>now }
              select[ filter[:revoked] ? :revoked : :created_at ] = range
            elsif filter.has_key?(:revoked)
              select[:revoked] = filter[:revoked] ? { :$ne=>nil } : { :$eq=>nil }
            end
            select[:client_id] = BSON::ObjectId(filter[:client_id].to_s) if filter[:client_id]
            collection.find(select).count
          end

          def historical(filter = {})
            days = filter[:days] || 60
            select = { :$gt=> { :created_at=>Time.now - 86400 * days } }
            select = {}
            if filter[:client_id]
              select[:client_id] = BSON::ObjectId(filter[:client_id].to_s)
            end
            raw = Server::AccessToken.collection.group("function (token) { return { ts: Math.floor(token.created_at / 86400) } }",
              select, { :granted=>0 }, "function (token, state) { state.granted++ }")
            raw.sort { |a, b| a["ts"] - b["ts"] }
          end
        end

        belongs_to :client
        property :token,       String, :key => true, :length => 72, :default => proc { Server.secure_random }
        property :channel,     String, :length => 72, :default => proc { Server.secure_random }
        property :identity,    String
        property :scope,       Json
        property :created_at,  DateTime, :default => proc { Time.now }
        property :expires_at,  DateTime
        property :revoked,     DateTime
        property :last_access, DateTime
        property :prev_access, DateTime

        # Updates the last access timestamp.
        def access!
          today = (Time.now.to_i / 3600) * 3600
          if last_access.nil? || last_access < today
            self.prev_access = last_access
            self.last_access = Time.at(today)
            self.save
          end
        end

        # Revokes this access token.
        def revoke!
          self.revoked = Time.at(Time.now.to_i)
          self.save
        end
      end

    end
  end
end
