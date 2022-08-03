package cl.gonzalo.app.models.dao;

import cl.gonzalo.app.models.documents.Usuario;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;

public interface UsuarioDao extends ReactiveMongoRepository<Usuario, String> {


}
