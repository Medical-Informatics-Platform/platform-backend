package hbp.mip.analysis;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.UUID;

public interface AnalysisRunRepository extends CrudRepository<AnalysisRunDAO, UUID> {

    // A bulk delete, so expired results are never loaded just to be removed.
    @Transactional
    @Modifying
    @Query("delete from AnalysisRunDAO run where run.created < :cutoff")
    int deleteCreatedBefore(@Param("cutoff") Date cutoff);
}
