/**
 * @license
 * Copyright 2019 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AuthProvider, ProviderId, SignInMethod } from '../providers';
import { Auth } from '../../model/auth';
import { AUTH_ERROR_FACTORY, AuthErrorCode } from '../errors';
import { IdTokenResponse, verifyTokenResponseUid } from '../../model/id_token';
import { signInWithCustomToken } from '../../api/authentication';
import { AuthCredential } from '../../model/auth_credential';

export class CustomTokenCredential implements AuthCredential {
  constructor(
    readonly customToken: string,
    readonly providerId: typeof CustomTokenProvider.PROVIDER_ID,
    readonly signInMethod: typeof CustomTokenProvider.SIGNIN_METHOD
  ) {}

  toJSON(): object {
    return {
      email: this.customToken,
      providerId: this.providerId,
      signInMethod: this.signInMethod
    };
  }

  getIdTokenResponse_(auth: Auth): Promise<IdTokenResponse> {
    return signInWithCustomToken(auth, { token: this.customToken });
  }

  linkToIdToken_(auth: Auth, idToken: string): Promise<IdTokenResponse> {
    throw AUTH_ERROR_FACTORY.create(AuthErrorCode.INTERNAL_ERROR, {
      appName: auth.name
    });
  }

  matchIdTokenWithUid_(auth: Auth, uid: string): Promise<IdTokenResponse> {
    return verifyTokenResponseUid(
      this.getIdTokenResponse_(auth),
      uid,
      auth.name
    );
  }
}

export class CustomTokenProvider implements AuthProvider {
  static readonly PROVIDER_ID = ProviderId.CUSTOM;
  static readonly SIGNIN_METHOD = SignInMethod.CUSTOM;
  readonly providerId: ProviderId = CustomTokenProvider.PROVIDER_ID;
  static credential(customToken: string): CustomTokenCredential {
    return new CustomTokenCredential(
      customToken,
      CustomTokenProvider.PROVIDER_ID,
      CustomTokenProvider.SIGNIN_METHOD
    );
  }
}
