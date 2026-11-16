package hbp.mip.study;

import hbp.mip.analysis.AnalysisDAO;
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
 * The membership of one analysis in one study, with its place in both orderings.
 *
 * Exactly one row per (study, analysis) — enforced by uq_study_member — is what makes
 * groups a strict partition: joining a group is a repoint of {@code analysisGroup}, so the previous group
 * gives the run up without a second delete.
 *
 * {@code analysisGroup} null means "in the study, ungrouped". Deleting the analysis drops the row
 * (ON DELETE CASCADE); the service nulls the field itself when a group is deleted, so the JPA state
 * matches the database rule instead of waiting for it.
 */
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "study_member")
public class StudyMemberDAO {

    @Id
    @Column(columnDefinition = "uuid", updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "study_id", columnDefinition = "uuid")
    private StudyDAO study;

    // Deliberately lazy and not batch-annotated: Hibernate 7 rejects @BatchSize on a to-one, and every
    // read here is `getAnalysis().getUuid()`, which a proxy answers from its identifier alone. The DTO
    // and the membership lookups therefore never issue a SELECT for the analysis itself.
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "analysis_uuid", columnDefinition = "uuid")
    private AnalysisDAO analysis;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "group_id", columnDefinition = "uuid")
    private AnalysisGroupDAO analysisGroup;

    @Column(name = "study_position", nullable = false)
    private Integer studyPosition;

    @Column(name = "group_position")
    private Integer groupPosition;

    public StudyMemberDAO(StudyDAO study, AnalysisDAO analysis, Integer studyPosition) {
        this.id = UUID.randomUUID();
        this.study = study;
        this.analysis = analysis;
        this.studyPosition = studyPosition;
    }

    /** Id comparison, not equals: one side may still be an uninitialized association proxy. */
    public boolean isIn(AnalysisGroupDAO group) {
        return analysisGroup != null && group.getId() != null && group.getId().equals(analysisGroup.getId());
    }
}
