package hbp.mip.folder;

import hbp.mip.experiment.ExperimentDAO;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

/**
 * The membership of one experiment in one folder, with its place in both orderings.
 *
 * Exactly one row per (folder, experiment) — enforced by uq_experiment_folder_member — is what makes
 * sets a strict partition: joining a set is a repoint of {@code experimentSet}, so the previous set
 * gives the run up without a second delete.
 *
 * {@code experimentSet} null means "in the folder, ungrouped". Deleting the experiment drops the row
 * (ON DELETE CASCADE); the service nulls the field itself when a set is deleted, so the JPA state
 * matches the database rule instead of waiting for it.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "experiment_folder_member")
public class ExperimentFolderMemberDAO {

    @Id
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "folder_id", columnDefinition = "uuid")
    private ExperimentFolderDAO folder;

    // Deliberately lazy and not batch-annotated: Hibernate 7 rejects @BatchSize on a to-one, and every
    // read here is `getExperiment().getUuid()`, which a proxy answers from its identifier alone. The DTO
    // and the membership lookups therefore never issue a SELECT for the experiment itself.
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "experiment_uuid", columnDefinition = "uuid")
    private ExperimentDAO experiment;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "set_id", columnDefinition = "uuid")
    private ExperimentSetDAO experimentSet;

    @Column(name = "folder_position", nullable = false)
    private Integer folderPosition;

    @Column(name = "set_position")
    private Integer setPosition;

    public ExperimentFolderMemberDAO(ExperimentFolderDAO folder, ExperimentDAO experiment, Integer folderPosition) {
        this.id = UUID.randomUUID();
        this.folder = folder;
        this.experiment = experiment;
        this.folderPosition = folderPosition;
    }

}
