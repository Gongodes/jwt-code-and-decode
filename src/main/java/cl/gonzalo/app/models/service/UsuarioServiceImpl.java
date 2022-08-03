package cl.gonzalo.app.models.service;

import cl.gonzalo.app.models.dao.UsuarioDao;
import cl.gonzalo.app.models.documents.Usuario;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class UsuarioServiceImpl implements UsuarioService{

    @Autowired
    private UsuarioDao dao;

    @Override
    public Flux<Usuario> findAll() {
        return dao.findAll();
    }

    @Override
    public Mono<Usuario> findById(String id) {
        return dao.findById(id);
    }

    @Override
    public Mono<Usuario> save(Usuario usuario) {
        return dao.save(usuario);
    }

    @Override
    public Mono<Void> delete(Usuario usuario) {
        return dao.delete(usuario);
    }
}
