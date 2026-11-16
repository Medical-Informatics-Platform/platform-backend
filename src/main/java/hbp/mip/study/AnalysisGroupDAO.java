package hbp.mip.study;

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
 * A named subset of a study's members: the unit the compare workspace renders as a section.
 *
 * Membership lives on {@link StudyMemberDAO#getAnalysisGroup()}, not here, because a run
 * can only ever sit in one group per study; a group is therefore just a name plus an ordering.
 *
 * Groups are their own namespace: a group may carry the same name as the study that holds it, but not
 * the same name as a sibling group (uq_analysis_group_study_name).
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "analysis_group")
public class AnalysisGroupDAO {

    @Id
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "study_id", columnDefinition = "uuid")
    private StudyDAO study;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String name;

    @Column(name = "sort_order", nullable = false)
    private Integer sortOrder;

    @Column(columnDefinition = "TIMESTAMP WITHOUT TIME ZONE")
    private Date created = new Date();

    public AnalysisGroupDAO(StudyDAO study, String name, Integer sortOrder) {
        this.id = UUID.randomUUID();
        this.study = study;
        this.name = name;
        this.sortOrder = sortOrder;
    }

}
