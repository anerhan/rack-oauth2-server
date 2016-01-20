module Rack
  module OAuth2
    class Server
      # Access token. This is what clients use to access resources.
      #
      # An access token is a unique code, associated with a client, an identity
      # and scope. It may be revoked, or expire after a certain period.
      class AccessToken < ActiveRecord

        scope :active,      lambda { where(revoked: nil) }
        scope :revoked,     lambda { where(arel_table[:revoked].not(nil)) }
        scope :not_expired, lambda {
          expires_at = AccessToken.arel_table[:expires_at]
          where(expires_at.eq(nil).or(expires_at.gt(Time.now)))
        }

        validates_uniqueness_of :token
        validates_uniqueness_of :channel, allow_nil: true
        belongs_to :client

        after_initialize :set_default_values

        class << self

          # Find AccessToken from token. Does not return revoked tokens.
          def from_token(token)
            find_by_token token
          end

          # Get an access token (create new one if necessary).
          #
          # You can set optional expiration in seconds. If zero or nil, token
          # never expires.
          def get_token_for(identity, client, scope, expires = nil)
            raise ArgumentError, "Identity must be String or Integer" unless String === identity || Integer === identity

            scope = Utils.normalize_scope(scope) & client.scope # Only allowed scope
            identity = identity.to_s

            active.not_expired.where({
              identity: identity,
              client_id: client.id,
              scope: scope.join(",")
            }).first || create_token_for(client, scope, identity, expires)
          end

          def when_expires(expires)
            expires.nil? ? nil : (Time.now.utc + expires.seconds)
          end

          def create_token_for(client, scope, identity = nil, expires = nil)
            expires_at = when_expires(expires)
            new(client: client, scope: scope, identity: identity, expires_at: expires_at).tap do |token|
              self.transaction do
                token.save!
                client.increment! :tokens_granted
              end
            end
          end

          # Find all AccessTokens for an identity.
          def from_identity(identity)
            find_by_identity identity
          end

          # Returns all access tokens for a given client, Use limit and offset
          # to return a subset of tokens, sorted by creation date.
          def for_client(client_id, offset = 0, limit = 100)
            if client = Client.find_by_id(client_id)
              client.access_tokens.offset(offset).limit(limit)
            else
              []
            end
          end

          # Returns count of access tokens.
          #
          # @param [Hash] filter Count only a subset of access tokens
          # @option filter [Integer] days Only count that many days (since now)
          # @option filter [Boolean] revoked Only count revoked (true) or non-revoked (false) tokens; count all tokens if nil
          # @option filter [String, ObjectId] client_id Only tokens grant to this client
          def count(filter = {})
            collection = all
            if filter[:days]
              now = Time.now.utc.to_i
              old = now - filter[:days].to_i.days

              collection = collection.where("date between ? and ?", old, now)
            end

            if filter.has_key?(:revoked)
              collection = collection.revoked
            end

            collection = collection.where(client_id: filter[:client_id]) if filter[:client_id]

            collection.count
          end

          def historical(filter = {})
            days = filter[:days] || 60

            collection = where("created_at > ?", Time.now - days.days)
            if filter[:client_id]
              collection = collection.where :client_id => filter[:client_id]
            end
          end

          def collection
            all
          end
        end

        # Updates the last access timestamp.
        def access!
          today = Time.now.utc
          if last_access.nil? || last_access < today
            update_attribute :last_access, today
          end
        end

        # Revokes this access token.
        def revoke!
          self.class.transaction do
            update_attribute :revoked, Time.now.utc
            client.increment! :tokens_revoked
          end
        end

        def scope= scope
          self[:scope] = scope.try :join, ","
        end

        def scope
          self[:scope].split(",")
        end

        def set_default_values(opts={})
          return if self.persisted?

          scope = begin
            Utils.normalize_scope(self.scope) & self.client.scope
          rescue
            []
          end

          self.expires_at = self.class.when_expires(Server.options.expires_in)
          self.token      = Server.secure_random
          self.channel    = Server.secure_random
          self.scope      = scope
          self.revoked    = nil
        end
      end # class
    end
  end
end
