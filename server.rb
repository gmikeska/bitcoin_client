require 'sinatra'
require 'sinatra/reloader'
require 'json'
require './lib/bitcoin'

also_reload('./lib/bitcoin')

get '/' do
  @client = BitcoinClient.set_up_connection()
  privKey = '18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725'
  pubkey = BitcoinClient.generate_public_key(privKey)
  address = BitcoinClient.base58_check(BitcoinClient.generate_address(pubkey)) 
  @msg = @client.get_address(address)[0]
  erb :index
end
