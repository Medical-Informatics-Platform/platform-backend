package hbp.mip.user;

import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<UserDAO, String> {
    UserDAO findByUsername(String username);
}
