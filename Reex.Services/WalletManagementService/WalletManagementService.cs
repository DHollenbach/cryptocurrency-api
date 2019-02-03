﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using NBitcoin;
using NBitcoin.RPC;
using Newtonsoft.Json;
using Reex.Models.v1.ApiRequest;
using Reex.Models.v1.Wallet;
using Reex.Services.FirebaseService;

namespace Reex.Services.WalletManagementService
{
    public class WalletManagementService : IWalletManagementService
    {
        #region constants
        private const string SYMBOL = "REEX";
        #endregion

        #region fields
        private readonly Network network;
        private readonly IFirebaseDbService firebaseDbService;
        private readonly string rpcUsername;
        private readonly string rpcPassword;
        private readonly string rpcEndpoint;
        private readonly int rpcMinconf;
        #endregion

        #region properties
        public RPCClient rpcClient => 
            new RPCClient($"{rpcUsername}:{rpcPassword}", rpcEndpoint, network);
        #endregion

        #region constructors
        public WalletManagementService(NBitcoin.Altcoins.Reex instance, IFirebaseDbService firebaseDbService, IConfiguration configuration)
        {
            network = instance.Mainnet;
            this.firebaseDbService = firebaseDbService;
            this.rpcUsername = configuration["RPCUsername"];
            this.rpcPassword = configuration["RPCPassword"];
            this.rpcEndpoint = configuration["RPCEndpoint"];
            this.rpcMinconf = int.Parse(configuration["RPCMinconf"] ?? "1");
        }
        #endregion

        #region public methods
        public async Task<IList<Wallet>> GetWallets(string id, string email)
        {
            var wallets = await firebaseDbService.GetWallets(id);
            return wallets;
        }

        public async Task<Wallet> GetWallet(Guid id, string email)
        {
            var wallet = await firebaseDbService.GetWallet(id);
            return wallet;
        }

        public async Task<IList<Address>> GetAddresses(Guid id)
        {
            var wallet = await firebaseDbService.GetWallet(id);
            return wallet.Addresses.Where(x => x.WalletId == id).ToList();
        }

        public async Task<Balance> GetBalance(Guid id, string email)
        {
            try
            {
                var wallet = await firebaseDbService.GetWallet(id);

                if(wallet is null)
                {
                    throw new ArgumentNullException(nameof(wallet));
                }

                var rpcResult = await rpcClient.SendCommandAsync(new RPCRequest(RPCOperations.getbalance, new object[] { wallet.WalletId.ToString(), rpcMinconf }));
                rpcResult.ThrowIfError();

                var balance = JsonConvert.DeserializeObject<decimal>(rpcResult.ResultString);
                var available_balance = balance;
                var confirmedBalance = balance;
                var reexBtcPrice = 0.0M;
                var reexUsdPrice = 0.0M;

                try
                {
                    using (var client = new HttpClient())
                    {
                        client.BaseAddress = new Uri("https://api.crex24.com/v2/public/tickers");

                        // Add an Accept header for JSON format.
                        client.DefaultRequestHeaders.Accept.Add(
                            new MediaTypeWithQualityHeaderValue("application/json"));

                        HttpResponseMessage btcReexPriceResponse = await client.GetAsync("?instrument=REEX-BTC");
                        if(btcReexPriceResponse.IsSuccessStatusCode)
                        {
                            reexBtcPrice = confirmedBalance * JsonConvert.DeserializeObject<IList<CoinPrice>>(await btcReexPriceResponse.Content.ReadAsStringAsync()).FirstOrDefault().Price;
                        }

                        HttpResponseMessage btcUsdPriceResponse = await client.GetAsync("?instrument=BTC-USD");
                        if(btcUsdPriceResponse.IsSuccessStatusCode)
                        {
                            reexUsdPrice = reexBtcPrice * JsonConvert.DeserializeObject<IList<CoinPrice>>(await btcUsdPriceResponse.Content.ReadAsStringAsync()).FirstOrDefault().Price;
                        }
                    }
                }
                catch
                {

                }

                return new Balance(available_balance, confirmedBalance, SYMBOL, true, reexBtcPrice, reexUsdPrice);
            }
            catch(Exception)
            {
                var balance = new Balance(0, 0, SYMBOL, true, 0, 0);
                balance.Status = "error";
                balance.Message = "An error occured while trying to get your balance";
                return balance;
            }
        }

        public async Task<TransactionWrapper> GetTransactions(Guid id, string email, int from, int count)
        {
            var wallet = await firebaseDbService.GetWallet(id);

            if (wallet is null)
            {
                throw new ArgumentNullException(nameof(wallet));
            }

            var rpcResult = await rpcClient.SendCommandAsync(new RPCRequest(RPCOperations.listtransactions, new object[] { wallet.WalletId.ToString(), count, from }));
            rpcResult.ThrowIfError();

            var result = JsonConvert.DeserializeObject<IList<Models.v1.Wallet.Transaction>>(rpcResult.ResultString);

            return new TransactionWrapper(result);
        }

        public async Task<WalletCreated> CreateWallet(CreateWallet request)
        {
            var walletId = Guid.NewGuid();
            var privateKey = new Key();
            var reexPrivateKey = privateKey.GetWif(network);
            var reexPublicKey = privateKey.PubKey.GetAddress(network);
            var walletLabel = "Main Wallet";
            var addressLabel = "Main Address";

            var address = new Address(Guid.NewGuid(), walletId, reexPublicKey.ToString(), addressLabel);
            var addresses = new List<Address>()
            {
              address
            };

            var wallet = new Wallet(walletId, request.Id, reexPrivateKey.ToString(), string.Empty, true, walletLabel, request.Email, addresses);

            // import new private key
            var rpcImportResult = await rpcClient.SendCommandAsync(new RPCRequest(RPCOperations.importprivkey, new object[] { wallet.PrivateKey, wallet.UserId.ToString(), true }));
            rpcImportResult.ThrowIfError();

            // create an account corresponding to the new address key
            var rpcResult = await rpcClient.SendCommandAsync(new RPCRequest(RPCOperations.setaccount, new object[] { address.MyAddress, wallet.WalletId.ToString() }));
            rpcResult.ThrowIfError();

            // save the data to CosmosDB
            await firebaseDbService.CreateWallet(wallet);

            return new WalletCreated(wallet.WalletId, reexPublicKey.ToString(), addressLabel);
        }

        public async Task<Address> CreateAddress(CreateWalletAddress request)
        {
            var wallet = await firebaseDbService.GetWallet(request.Id);
            var privateKey = new BitcoinSecret(wallet.PrivateKey);
            var extKey = new ExtKey(privateKey.PubKey.ToHex());
            var newAddress = new Address(Guid.NewGuid(), wallet.WalletId, extKey.PrivateKey.PubKey.GetAddress(network).ToString(), request.Label);
            wallet.Addresses.Add(newAddress);

            var walletKey = await firebaseDbService.GetWalletKey(request.Id);

            if(string.IsNullOrWhiteSpace(walletKey))
            {
                throw new InvalidOperationException("Could not get the wallet you are looking for.");
            }

            var updateWallet = await firebaseDbService.UpdateWallet(walletKey, wallet);

            return newAddress;
        }

        public async Task<CoinTransfer> SpendCoins(SpendCoins request)
        {
            var wallet = await firebaseDbService.GetWallet(request.Id);

            if (wallet is null)
            {
                throw new ArgumentNullException(nameof(wallet));
            }

            if(string.IsNullOrWhiteSpace(request.ToAddress))
            {
                throw new ArgumentNullException(nameof(request.ToAddress));
            }

            var addressBalanceResult = await this.GetBalance(request.Id, request.Email);

            decimal addressBalance = addressBalanceResult.AvailableBalance;
            decimal addressBalanceConfirmed = addressBalanceResult.ConfirmedBalance;

            var info = await this.GetInfo();
            if ((request.transferValue + info.RelayFee) >= addressBalanceConfirmed)
            {
                throw new Exception($"The address doesn't have enough funds! Relay fee {info.RelayFee} + {request.transferValue} = {(request.transferValue + info.RelayFee)}");
            }

            var rpcResult = await rpcClient.SendCommandAsync(new RPCRequest(RPCOperations.sendfrom, new object[] { wallet.WalletId.ToString(), request.ToAddress, request.transferValue }));
            rpcResult.ThrowIfError();

            return new CoinTransfer();
        }

        public async Task<BlockChainInfo> GetInfo()
        {
            var rpcResult = await rpcClient.SendCommandAsync(new RPCRequest(RPCOperations.getinfo, new object[] { }));
            rpcResult.ThrowIfError();

            return JsonConvert.DeserializeObject<BlockChainInfo>(rpcResult.ResultString);
        }
        #endregion
    }
}
