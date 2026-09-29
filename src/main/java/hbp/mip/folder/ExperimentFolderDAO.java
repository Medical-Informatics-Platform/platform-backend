package hbp.mip.folder;

import hbp.mip.user.UserDAO;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Table;
import lombok.Getter;
import org.hibernate.annotations.BatchSize;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * A user-curated group of experiment runs (an "analysis set" in the UI).
 *
 * The folder owns its sets and its members: deleting a folder takes its grouping with it, never the
 * experiments themselves, which stay in the experiment table.
 *
 * Names are unique per owner ignoring case (uq_experiment_folder_owner_name), and the service
 * rejects the duplicate with 409 before the database ever sees it.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "experiment_folder")
public class ExperimentFolderDAO {

    @Id
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_username", columnDefinition = "CHARACTER VARYING")
    private UserDAO owner;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String name;

    @Column(name = "sort_order", nullable = false)
    private Integer sortOrder;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date created = new Date();

    // Batched rather than join-fetched: two bags on one entity cannot be fetched in a single join, and
    // the list endpoint reads many folders at once, so one statement per collection beats one per folder.
    @BatchSize(size = 50)
    @OneToMany(mappedBy = "folder", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("sortOrder ASC")
    private List<ExperimentSetDAO> sets = new ArrayList<>();

    @BatchSize(size = 50)
    @OneToMany(mappedBy = "folder", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("folderPosition ASC")
    private List<ExperimentFolderMemberDAO> members = new ArrayList<>();

    public ExperimentFolderDAO(UserDAO owner, String name, Integer sortOrder) {
        this.id = UUID.randomUUID();
        this.owner = owner;
        this.name = name;
        this.sortOrder = sortOrder;
    }

}
