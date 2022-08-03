package cl.gonzalo.app.controllers;

import cl.gonzalo.app.models.documents.Usuario;
import cl.gonzalo.app.models.service.UsuarioService;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;


@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
    KeyPair rsaKeyPair = rsaGen.generateKeyPair();
    RSAPublicKey rsaPublicKey = (RSAPublicKey)rsaKeyPair.getPublic();

    @Autowired
    private UsuarioService service;

    public UsuarioController() throws NoSuchAlgorithmException {
    }

    @GetMapping
    public Flux<Usuario> listar(){
        return service.findAll();
    }

    @GetMapping("/{id}")
    public Mono<Usuario> ver(@PathVariable String id) {
        return service.findById(id).flatMap(u -> {



            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)rsaKeyPair.getPrivate();
            RSADecrypter decrypter = new RSADecrypter(rsaPrivateKey);

            JWEObject object = null;
            try {
                object = JWEObject.parse(u.getContraseña());
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
            try {
                object.decrypt(decrypter);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }
            String jws = object.getPayload().toString();
            String[] chunks = jws.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();

            String payload = new String(decoder.decode(chunks[1]));
            System.out.println(payload);
            String[] split2 = payload.split("\"");
            u.setContraseña(split2[17]);



            return Mono.just(u);
    });

    }
    @PostMapping
    public Mono<Usuario> crear(@RequestBody Usuario usuario) {
        return service.save(usuario);
    }

    @PutMapping("/{id}")
    public Mono<Usuario> editar(@RequestBody Usuario usuario, @PathVariable String id) {
        return service.findById(id).flatMap(u -> {
            u.setNombre(usuario.getNombre());

            JWSHeader headerJWS = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .contentType("text/plain")
                    .customParam("exp", new Date().getTime())
                    .build();



            JWTClaimsSet claimsJWS = new JWTClaimsSet.Builder()
                    .issuer("me")
                    .audience("you")
                    .subject("bob")
                    .expirationTime(Date.from(Instant.now().plusSeconds(120)))
                    .claim("DATA", usuario.getContraseña())
                    .build();

            SignedJWT signedJWT = new SignedJWT(headerJWS, claimsJWS);
            JWSSigner signer = null;
            try {
                signer = new MACSigner(new byte[256]);
            } catch (KeyLengthException e) {
                throw new RuntimeException(e);
            }
            try {
                signedJWT.sign(signer);
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }


            JWEAlgorithm alg = JWEAlgorithm.RSA_OAEP_256;
            EncryptionMethod enc = EncryptionMethod.A256GCM;


            KeyPairGenerator rsaGen = null;
            try {
                rsaGen = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }





            KeyGenerator keyGenerator = null;
            try {
                keyGenerator = KeyGenerator.getInstance("AES");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            keyGenerator.init(enc.cekBitLength());
            SecretKey cek = keyGenerator.generateKey();


            JWEHeader header = new JWEHeader(alg, enc);
            Payload jws1 = new Payload(signedJWT);

            JWEObject jwe = new JWEObject(header, jws1);
            try {
                jwe.encrypt(new RSAEncrypter(rsaPublicKey, cek));
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }


            u.setContraseña( jwe.serialize());

            return service.save(u);
        });
    }

    @DeleteMapping("/{id}")
    public Mono<Usuario> borrar(@PathVariable String id) {
        return  service.findById(id).flatMap(u -> {
            return service.delete(u).then(Mono.just(u));
        });
    }
}
