package hbp.mip.folder;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Folder persistence. Ownership filtering happens in the service, on the user resolved from the token,
 * so no query here is asked to trust an id that came from a request.
 *
 * JpaRepository rather than CrudRepository for two reasons: {@code saveAndFlush} writes inside the
 * service transaction, so a unique-name race surfaces where it can still be answered 409 instead of
 * arriving too late, at commit time, as a 500; and {@code findByIdForUpdate} locks the folder row so
 * membership writes on one folder serialize instead of racing the member unique constraint.
 */
public interface ExperimentFolderRepository extends JpaRepository<ExperimentFolderDAO, UUID> {

    /** The owner's folders in display order. Every folder-scoped read starts from here. */
    @Query("select folder from ExperimentFolderDAO folder "
            + "where folder.owner.username = :username order by folder.sortOrder asc, folder.id asc")
    List<ExperimentFolderDAO> findOwnedFolders(@Param("username") String username);

    /**
     * The folder, write-locked for the rest of the transaction. Member and set writes take this first,
     * so the "is it already a member?" check runs after the competing writer committed and a duplicate
     * insert is not attempted at all. Reads must keep using {@code findById}.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select folder from ExperimentFolderDAO folder where folder.id = :id")
    Optional<ExperimentFolderDAO> findByIdForUpdate(@Param("id") UUID id);
}
