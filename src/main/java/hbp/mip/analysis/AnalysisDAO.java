package hbp.mip.analysis;

import hbp.mip.user.UserDAO;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
@Table(name = "`analysis`")
public class AnalysisDAO {

    @Id
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID uuid;

    @Column(columnDefinition = "TEXT")
    private String name;

    @ManyToOne
    @JoinColumn(name = "created_by_username", columnDefinition = "CHARACTER VARYING")
    private UserDAO createdBy;

    @Column(columnDefinition = "TEXT")
    @Enumerated(EnumType.STRING)
    private Status status;

    @Column(columnDefinition = "TEXT")
    private String result;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date finished;

    // The AnalysisRequestDTO the result was computed from, as JSON.
    @Column(name = "analysis_request", columnDefinition = "TEXT")
    private String analysisRequest;

    @Column(name = "algorithm_id", columnDefinition = "TEXT")
    private String algorithmId;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date created = new Date();

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date updated;

    @Column(columnDefinition = "BOOLEAN")
    private boolean shared = false;

    @Column(name = "mip_version", columnDefinition = "TEXT")
    private String mipVersion;

    // Whether the analysis's result have been viewed by its owner
    @Column(columnDefinition = "BOOLEAN")
    private boolean viewed = false;

    public enum Status {
        error,
        pending,
        success
    }

}
