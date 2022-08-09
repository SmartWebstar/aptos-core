// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

import React, { useMemo } from 'react';
import AuthLayout from 'core/layouts/AuthLayout';
import Routes, { Routes as PageRoutes } from 'core/routes';
import CreateAccountBody from 'core/components/CreateAccountBody';
import { CreateAccountFormValues, CreateAccountLayout } from 'core/layouts/AddAccountLayout';
import { useNavigate } from 'react-router-dom';
import { AptosAccount } from 'aptos';
import { generateMnemonic, generateMnemonicObject } from 'core/utils/account';
import useGlobalStateContext from 'core/hooks/useGlobalState';
import useFundAccount from 'core/mutations/faucet';
import { createAccountErrorToast, createAccountToast } from 'core/components/Toast';

function CreateAccount() {
  const navigate = useNavigate();
  const { addAccount } = useGlobalStateContext();
  const { fundAccount } = useFundAccount();
  const newMnemonic = useMemo(() => generateMnemonic(), []);

  const onSubmit = async (data: CreateAccountFormValues, event?: React.BaseSyntheticEvent) => {
    const { mnemonicString, secretRecoveryPhrase } = data;
    event?.preventDefault();

    if (secretRecoveryPhrase) {
      try {
        const { mnemonic, seed } = await generateMnemonicObject(mnemonicString);
        const aptosAccount = new AptosAccount(seed);
        const {
          address,
          privateKeyHex,
          publicKeyHex,
        } = aptosAccount.toPrivateKeyObject();

        await addAccount({
          address: address!,
          mnemonic,
          name: 'Wallet',
          privateKey: privateKeyHex,
          publicKey: publicKeyHex!,
        });

        if (fundAccount) {
          await fundAccount({ address: address!, amount: 0 });
        }

        createAccountToast();
        navigate(Routes.wallet.routePath);
      } catch (err) {
        createAccountErrorToast();
        // eslint-disable-next-line no-console
        console.error(err);
      }
    }
  };

  return (
    <AuthLayout routePath={PageRoutes.createAccount.routePath}>
      <CreateAccountLayout
        headerValue="Create account"
        backPage={Routes.addAccount.routePath}
        defaultValues={{
          mnemonic: newMnemonic.split(' '),
          mnemonicString: newMnemonic,
          secretRecoveryPhrase: false,
        }}
        onSubmit={onSubmit}
      >
        <CreateAccountBody />
      </CreateAccountLayout>
    </AuthLayout>
  );
}

export default CreateAccount;