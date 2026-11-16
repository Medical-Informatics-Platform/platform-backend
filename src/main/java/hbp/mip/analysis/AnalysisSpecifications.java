package hbp.mip.analysis;

import hbp.mip.utils.Exceptions.BadRequestException;
import jakarta.persistence.criteria.*;
import lombok.NonNull;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class AnalysisSpecifications {
    public static class AnalysisWithName implements Specification<AnalysisDAO> {

        private final String name;

        public AnalysisWithName(String name) {
            this.name = name;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            if (name == null) {
                return cb.isTrue(cb.literal(true));
            }

            String regExp = (name.contains("%") ? name : name + "%");
            return cb.like(cb.lower(root.get("name")), regExp.toLowerCase());
        }
    }

    public static class AnalysisWithAlgorithm implements Specification<AnalysisDAO> {

        private final String algorithm;

        public AnalysisWithAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            if (algorithm == null) {
                return cb.isTrue(cb.literal(true));
            }

            // The algorithm name lives in algorithm_id; analysis_request holds the whole execution request JSON.
            return cb.equal(cb.lower(root.get("algorithmId")), this.algorithm.toLowerCase());
        }
    }

    public static class AnalysisWithViewed implements Specification<AnalysisDAO> {

        private final Boolean viewed;

        public AnalysisWithViewed(Boolean viewed) {
            this.viewed = viewed;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> query,
                @NonNull CriteriaBuilder cb) {
            if (viewed == null) {
                return cb.isTrue(cb.literal(true)); // always true = no filtering
            }
            return cb.equal(root.get("viewed"), this.viewed);
        }
    }

    public static class AnalysisWithShared implements Specification<AnalysisDAO> {

        private final Boolean shared;

        public AnalysisWithShared(Boolean shared) {
            this.shared = shared;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            if (shared == null) {
                return cb.isTrue(cb.literal(true));
            }
            return cb.equal(root.get("shared"), this.shared);
        }
    }

    public static class MyAnalysis implements Specification<AnalysisDAO> {

        private final String username;

        public MyAnalysis(String username) {
            this.username = username;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            if (username == null) {
                return cb.isTrue(cb.literal(true));
            }
            Join<Object, Object> analysisDAOUserDAOJoin = root.join("createdBy");
            return cb.equal(analysisDAOUserDAOJoin.get("username"), username);
        }
    }

    public static class NotMyAnalysis implements Specification<AnalysisDAO> {

        private final String username;

        public NotMyAnalysis(String username) {
            this.username = username;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            if (username == null) {
                return cb.isTrue(cb.literal(true));
            }
            Join<Object, Object> analysisDAOUserDAOJoin = root.join("createdBy");
            return cb.notEqual(analysisDAOUserDAOJoin.get("username"), username);
        }
    }

    public static class SharedAnalysis implements Specification<AnalysisDAO> {

        private final boolean shared;

        public SharedAnalysis(boolean shared) {
            this.shared = shared;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            if (!shared) {
                return cb.isTrue(cb.literal(false));
            }
            return cb.equal(root.get("shared"), true);
        }
    }

    /**
     * Every dataset the analysis ran on is allowed for its data model. {@code allowedDatasets} is a JSON object
     * from data model to the lowercase dataset codes and labels the user may use (ClaimUtils.usableDatasets).
     */
    public static class DatasetsReadable implements Specification<AnalysisDAO> {

        private final String allowedDatasets;

        public DatasetsReadable(String allowedDatasets) {
            this.allowedDatasets = allowedDatasets;
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            // Defined in V6__AnalysisStudyTerminology.sql, replaced by V7.
            return cb.isTrue(cb.function("analysis_datasets_readable", Boolean.class,
                    root.get("analysisRequest"), cb.literal(allowedDatasets)));
        }
    }

    public static class AnalysisOrderBy implements Specification<AnalysisDAO> {

        private final String orderBy;
        private final Boolean descending;

        public AnalysisOrderBy(String orderBy, Boolean descending) {
            if (properColumnToBeOrderedBy(orderBy))
                // Sorting "algorithm" means by the algorithm name stored in algorithm_id.
                this.orderBy = "algorithm".equals(orderBy) ? "algorithmId" : orderBy;
            else
                throw new BadRequestException("Please provide proper column to order by.");
            this.descending = Objects.requireNonNullElse(descending, true);
        }

        public Predicate toPredicate(@NonNull Root<AnalysisDAO> root, @NonNull CriteriaQuery<?> criteriaQuery,
                @NonNull CriteriaBuilder cb) {
            if (descending) {
                criteriaQuery.orderBy(cb.desc(root.get(orderBy)));
            } else {
                criteriaQuery.orderBy(cb.asc(root.get(orderBy)));
            }
            return cb.isTrue(cb.literal(true));
        }

    }

    public static boolean properColumnToBeOrderedBy(String column) {
        {
            List<String> properColumns = new ArrayList<>();
            properColumns.add("uuid");
            properColumns.add("name");
            properColumns.add("created_by_username");
            properColumns.add("algorithm");
            properColumns.add("created");
            properColumns.add("status");
            properColumns.add("shared");
            properColumns.add("viewed");
            return properColumns.contains(column);
        }
    }
}
