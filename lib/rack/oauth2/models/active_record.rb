module Rack
  module OAuth2
    class Server

      class ActiveRecord < ::ActiveRecord::Base
        self.abstract_class     = true
        self.table_name_prefix  = "oauth2_provider_"
      end

      class << self
        # Create new instance of the klass and populate its attributes.
        def new_instance(klass, fields)
          instance = klass.new fields
        end
      end

      class CreateRackOauth2ServerSchema < ::ActiveRecord::Migration
        def change

          create_table Client.table_name do |t|
            # Client identifier.
            t.string :client_id
            # Client secret: random, long, and hexy.
            t.string :secret
            # User see this.
            t.string :display_name
            # Link to client's Web site.
            t.string :link
            # Preferred image URL for this icon.
            t.string :image_url
            # Redirect URL. Supplied by the client if they want to restrict redirect URLs (better security).
            t.string :redirect_uri
            # List of scope the client is allowed to request.
            t.string :scope
            # Free form fields for internal use.
            t.string :notes
            # Timestamp if revoked.
            t.datetime :revoked
            # Counts how many access tokens were granted.
            t.integer :tokens_granted
            # Counts how many access tokens were revoked.
            t. integer :tokens_revoked

            t.timestamps
          end
          change_table Client.table_name do |t|
            t.index :client_id
            t.index [:client_id, :secret]
          end

          create_table AuthRequest.table_name do |t|
            # Client making this request.
            t.integer :client_id
            # scope of this request: array of names.
            t.string :scope
            # Redirect back to this URL.
            t.string :redirect_uri
            # Client requested we return state on redirect.
            t.string :state
            # Response type: either code or token.
            t.string :response_type
            # If granted, the access grant code.
            t.string :grant_code
            # If granted, the access token.
            t.string :access_token
            # Keeping track of things.
            t.datetime :authorized_at
            # Timestamp if revoked.
            t.datetime :revoked

            t.timestamps
          end
          change_table AuthRequest.table_name do |t|
            t.index :client_id
          end

          create_table AccessToken.table_name do |t|
            # Client that was granted this access token.
            t.integer :client_id
            # The scope granted to this token.
            t.string :scope
            # Uniq token
            t.string :token
            # The identity we authorized access to.
            t.string :identity
            # When token expires for good.
            t.datetime :expires_at
            # Timestamp if revoked.
            t.datetime :revoked
            # Timestamp of last access using this token, rounded up to hour.
            t.datetime :last_access
            # Timestamp of previous access using this token, rounded up to hour.
            t.datetime :prev_access

            t.timestamps
          end
          change_table AccessToken.table_name do |t|
            t.index :client_id
            t.index :token
          end

          create_table AccessGrant.table_name do |t|
            # Client that was granted this access token.
            t.integer :client_id
            # The scope granted to this token.
            t.string :scope
            # The identity we authorized access to.
            t.string :identity
            # Secret code
            t.string :code
            # Redirect URI for this grant.
            t.string :redirect_uri
            # When token expires for good.
            t.datetime :expires_at
            # Tells us when (and if) access token was created.
            t.datetime :granted_at
            # Timestamp if revoked.
            t.datetime :revoked
            # Access token created from this grant. Set and spent.
            t.string :access_token


            t.timestamps
          end
          change_table AccessGrant.table_name do |t|
            t.index :client_id
            t.index :code
          end

        end
      end

      class CreateRackOauth2ServerSchemaWithChannel < ::ActiveRecord::Migration
        def change
          # Secret channel for websockets personal thread
          add_column AccessToken.table_name, :channel, :string
          add_index  AccessToken.table_name, :channel
        end
      end

      class CreateRackOauth2ServerSchemaWithCatapush < ::ActiveRecord::Migration
        def change
          # Secret password for Catapush thread
          add_column AccessToken.table_name, :password, :string
          add_index  AccessToken.table_name, :password
        end
      end

    end
  end
end


require "rack/oauth2/models/active_record/client"
require "rack/oauth2/models/active_record/auth_request"
require "rack/oauth2/models/active_record/access_grant"
require "rack/oauth2/models/active_record/access_token"
require "rack/oauth2/models/active_record/issuer"
