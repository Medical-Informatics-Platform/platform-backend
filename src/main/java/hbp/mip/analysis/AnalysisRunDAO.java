package hbp.mip.analysis;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.UUID;

/**
 * A successful studio run kept until its owner saves it or it expires. Saving copies it into an
 * {@link AnalysisDAO}, so the stored result is the one the user reviewed and the analysis is not
 * executed again.
 */
@Entity
@Data
@NoArgsConstructor
@Table(name = "analysis_run")
public class AnalysisRunDAO {

    @Id
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID uuid;

    @Column(name = "created_by_username", columnDefinition = "CHARACTER VARYING")
    private String createdByUsername;

    @Column(columnDefinition = "TEXT")
    private String result;

    // The AnalysisRequestDTO the result was computed from, as JSON.
    @Column(name = "analysis_request", columnDefinition = "TEXT")
    private String analysisRequest;

    @Column(name = "algorithm_id", columnDefinition = "TEXT")
    private String algorithmId;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date created;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date finished;

    @Column(name = "mip_version", columnDefinition = "TEXT")
    private String mipVersion;
}
