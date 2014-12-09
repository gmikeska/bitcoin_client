require 'chain'
require 'ecdsa'
require 'securerandom'
require 'digest'
require 'base58'
require 'openssl'
require 'scrypt'
BASE58_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
module BitcoinClient

  def self.set_up_connection()

    chain_api_key = '00e09e6077be3b3ec468768dab1220e3'
    chain_key_secret = '  6af5b2d58c55cce650886c5a739d0286'
    
    Chain::Client.new(key_id: chain_api_key, key_secret: chain_key_secret)
  end

  class KeySet

    attr_reader :private_key, :public_key, :addresses

    def initialize(*args)
      @private_key
      @public_key
      @addresses = []
      case args.length
      when 0
        create_private_key
      when 1
        set_private_key(args[0])
      end
      generate_public_key
      generate_address
      p args.length
    end

    def create_private_key()
      group = ECDSA::Group::Secp256k1
      private_key = 1 + SecureRandom.random_number(group.order - 1)
      @private_key = private_key.to_s(16)
    end
    def set_private_key(pk)
      @private_key = pk

    end
    def generate_public_key()
      # Having a private ECDSA key (private_key)
      private_key = @private_key.to_i(16)
      p "0 #{private_key}"
      group = ECDSA::Group::Secp256k1
      public_key_coords = group.generator.multiply_by_scalar(private_key) #Take the corresponding public key generated with it (65 bytes)
      pubkey = "04#{public_key_coords.x.to_s(16)}#{public_key_coords.y.to_s(16)}".upcase() #1 byte 0x04, 32 bytes corresponding to X coordinate, 32 bytes corresponding to Y coordinate
      @public_key = pubkey
    end

    def generate_address()
      sha_result = (Digest::SHA2.new << [@public_key].pack("H*")).to_s #Perform SHA-256 hashing on the public key
      ripe = (Digest::RMD160.new << [sha_result].pack("H*")).to_s
      extended = "00#{ripe}"
      sha_result = (Digest::SHA2.new << [extended].pack("H*")).to_s
      sha_result2 = (Digest::SHA2.new << [sha_result].pack("H*")).to_s
      checksum = sha_result2[0,8]
      binaryAddress = extended+checksum
      @addresses.push(BitcoinClient::KeySet.base58_check(binaryAddress))
    end

    def self.base58_check(binaryAddress)
        lz = 0 
        iterator = 0
        x = binaryAddress.to_i(16)
        while binaryAddress[iterator, iterator+1] == "0" do
          lz+=1
          iterator+=2
        end

        code_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        output_string = ""
        while x > 0 do
          rem = x%58
          output_string = "#{output_string}#{code_string[rem]}"
          x=x/58

        end
        p lz
        lz.times do
          output_string = "#{output_string}1"
        end

        output_string.reverse
      end



    end
end