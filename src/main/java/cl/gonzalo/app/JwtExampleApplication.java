package cl.gonzalo.app;

import cl.gonzalo.app.models.documents.Usuario;
import cl.gonzalo.app.models.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.core.ReactiveMongoTemplate;
import reactor.core.publisher.Flux;

import java.util.Date;

@SpringBootApplication
public class JwtExampleApplication implements CommandLineRunner  {

	public static void main(String[] args) {
		SpringApplication.run(JwtExampleApplication.class, args);
	}

	@Autowired
	private UsuarioService service;

	@Autowired
	private ReactiveMongoTemplate mongoTemplate;

	@Override
	public void run(String... args) throws Exception {

		mongoTemplate.dropCollection("usuario").subscribe();

		Flux.just(
				new Usuario("Gonzalo", ""),
				new Usuario("Jhon", ""),
				new Usuario("Patricio", "")


		).flatMap(u -> {

			return service.save(u);
		})

				.subscribe();

	}
}
