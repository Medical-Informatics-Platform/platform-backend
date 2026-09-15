package hbp.mip.folder;

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

import java.util.Date;
import java.util.UUID;

/**
 * A named subset of a folder's members: the unit the compare workspace renders as a section.
 *
 * Membership lives on {@link ExperimentFolderMemberDAO#getExperimentSet()}, not here, because a run
 * can only ever sit in one set per folder; a set is therefore just a name plus an ordering.
 *
 * Sets are their own namespace: a set may carry the same name as the folder that holds it, but not
 * the same name as a sibling set (uq_experiment_set_folder_name).
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "experiment_set")
public class ExperimentSetDAO {

    @Id
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "folder_id", columnDefinition = "uuid")
    private ExperimentFolderDAO folder;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String name;

    @Column(name = "sort_order", nullable = false)
    private Integer sortOrder;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date created = new Date();

    public ExperimentSetDAO(ExperimentFolderDAO folder, String name, Integer sortOrder) {
        this.id = UUID.randomUUID();
        this.folder = folder;
        this.name = name;
        this.sortOrder = sortOrder;
    }

}
