package hbp.mip.experiment;

import hbp.mip.user.UserDAO;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
@Table(name = "`experiment`")
public class ExperimentDAO {

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

    @Column(columnDefinition = "TEXT")
    private String algorithm;

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

    // Whether the experiment's result have been viewed by its owner
    @Column(columnDefinition = "BOOLEAN")
    private boolean viewed = false;

    public enum Status {
        error,
        pending,
        success
    }

}
