package cl.gonzalo.app.models.service;

import cl.gonzalo.app.models.documents.Usuario;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


public interface UsuarioService {

    public Flux<Usuario> findAll();

    public Mono<Usuario> findById(String id);

    public Mono<Usuario> save(Usuario Usuario);

    public Mono<Void> delete(Usuario Usuario);
}
