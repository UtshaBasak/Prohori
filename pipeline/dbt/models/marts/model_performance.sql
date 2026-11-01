-- Flow-model performance per evaluation, averaged over seeds, with the change since the
-- previous evaluation of the same model, variant and operating point.
with runs as (
    select
        evaluated_at,
        evaluated_date,
        dataset,
        variant,
        model,
        operating_point,
        count(*) as seeds,
        avg(recall) as recall,
        avg(precision) as precision,
        avg(fpr) as fpr,
        avg(false_alerts_per_10k) as false_alerts_per_10k,
        avg(pr_auc) as pr_auc,
        avg(roc_auc) as roc_auc
    from {{ ref('stg_model_evaluations') }}
    group by evaluated_at, evaluated_date, dataset, variant, model, operating_point
)

select
    *,
    recall - lag(recall) over (
        partition by dataset, variant, model, operating_point order by evaluated_at
    ) as recall_change,
    pr_auc - lag(pr_auc) over (
        partition by dataset, variant, model, operating_point order by evaluated_at
    ) as pr_auc_change
from runs
