package hbp.mip.study;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Study persistence. Ownership filtering happens in the service, on the user resolved from the token,
 * so no query here is asked to trust an id that came from a request.
 *
 * JpaRepository rather than CrudRepository for two reasons: {@code saveAndFlush} writes inside the
 * service transaction, so a unique-name race surfaces where it can still be answered 409 instead of
 * arriving too late, at commit time, as a 500; and {@code findByIdForUpdate} locks the study row so
 * membership writes on one study serialize instead of racing the member unique constraint.
 */
public interface StudyRepository extends JpaRepository<StudyDAO, UUID> {

    /** The owner's studies in display order. Every study-scoped read starts from here. */
    @Query("select study from StudyDAO study "
            + "where study.owner.username = :username order by study.sortOrder asc, study.id asc")
    List<StudyDAO> findOwnedStudies(@Param("username") String username);

    /**
     * The study, write-locked for the rest of the transaction. Member and group writes take this first,
     * so the "is it already a member?" check runs after the competing writer committed and a duplicate
     * insert is not attempted at all. Reads must keep using {@code findById}.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select study from StudyDAO study where study.id = :id")
    Optional<StudyDAO> findByIdForUpdate(@Param("id") UUID id);
}
