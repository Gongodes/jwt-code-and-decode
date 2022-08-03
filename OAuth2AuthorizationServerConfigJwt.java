// this is based on code from https://www.baeldung.com/spring-security-oauth-jwt
// also based on code from https://connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt and https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-encryption
// used com.nimbusds:nimbus-jose-jwt:6.4.2
// interesting bits at lines 120 - 188

/**
* THIS IS JUST A PROOF OF CONCEPT. DO NOT USE IN PRODUCTION.
*/
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;

@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfigJwt extends AuthorizationServerConfigurerAdapter {

	@Autowired
	@Qualifier("authenticationManagerBean")
	private AuthenticationManager authenticationManager;

	@Override
	public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient("sampleClientId").authorizedGrantTypes("implicit")
				.scopes("read", "write", "foo", "bar").autoApprove(false).accessTokenValiditySeconds(3600)
				.redirectUris("http://localhost:8083/")

				.and().withClient("fooClientIdPassword").secret(passwordEncoder().encode("secret"))
				.authorizedGrantTypes("password", "authorization_code", "refresh_token").scopes("foo", "read", "write")
				.accessTokenValiditySeconds(3600)
				// 1 hour
				.refreshTokenValiditySeconds(2592000)
				// 30 days
				.redirectUris("xxx", "http://localhost:8089/", "http://localhost:8080/login/oauth2/code/custom")

				.and().withClient("barClientIdPassword").secret(passwordEncoder().encode("secret"))
				.authorizedGrantTypes("password", "authorization_code", "refresh_token").scopes("bar", "read", "write")
				.accessTokenValiditySeconds(3600)
				// 1 hour
				.refreshTokenValiditySeconds(2592000) // 30 days

				.and().withClient("testImplicitClientId").authorizedGrantTypes("implicit")
				.scopes("read", "write", "foo", "bar").autoApprove(true).redirectUris("xxx");

	}

	@Bean
	@Primary
	public DefaultTokenServices tokenServices() {
		final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
		defaultTokenServices.setTokenStore(tokenStore());
		defaultTokenServices.setSupportRefreshToken(true);
		return defaultTokenServices;
	}

	@Override
	public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
		tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), accessTokenConverter()));
		endpoints.tokenStore(tokenStore()).tokenEnhancer(tokenEnhancerChain)
				.authenticationManager(authenticationManager);

	}

	@Bean
	public TokenStore tokenStore() {

		return new JwtTokenStore(accessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accessTokenConverter() {
		final JwtAccessTokenConverter converter = new JwtJweAccessTokenConverter();
		final KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("mytest.jks"),
				"mypass".toCharArray());
		converter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"));
		return converter;
	}

	public class JwtJweAccessTokenConverter extends JwtAccessTokenConverter {

		RSAKey recipientJWK, recipientPublicJWK;

		public JwtJweAccessTokenConverter() {
			try {
				recipientJWK = new RSAKeyGenerator(2048).keyID("456").keyUse(KeyUse.ENCRYPTION).generate();
				recipientPublicJWK = recipientJWK.toPublicJWK();
			} catch (JOSEException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		@Override
		protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			String jwt = super.encode(accessToken, authentication);

			try {
				// jwt is already signed at this point (by JwtAccessTokenConverter)
				SignedJWT parsed = SignedJWT.parse(jwt);

				// Create JWE object with signed JWT as payload
				JWEObject jweObject = new JWEObject(
						new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT") // required
																														// to
																														// indicate
																														// nested
																														// JWT
								.build(),
						new Payload(parsed));

				// Encrypt with the recipient's public key
				jweObject.encrypt(new RSAEncrypter(recipientPublicJWK));

				// Serialise to JWE compact form
				String jweString = jweObject.serialize();

				return jweString;
			} catch (Exception e) {
				e.printStackTrace();
			}

			return jwt;
		}

		@Override
		protected Map<String, Object> decode(String token) {
			try {
				// basically treat the incoming token as an encrypted JWT
				EncryptedJWT parse = EncryptedJWT.parse(token);
				// decrypt it
				RSADecrypter dec = new RSADecrypter(recipientJWK);
				parse.decrypt(dec);
				// content of the encrypted token is a signed JWT (signed by
				// JwtAccessTokenConverter)
				SignedJWT signedJWT = parse.getPayload().toSignedJWT();
				// pass on the serialized, signed JWT to JwtAccessTokenConverter
				return super.decode(signedJWT.serialize());

			} catch (ParseException e) {
				e.printStackTrace();
			} catch (JOSEException e) {
				e.printStackTrace();
			}

			return super.decode(token);
		}
	}

	@Bean
	public TokenEnhancer tokenEnhancer() {
		return new CustomTokenEnhancer();
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}