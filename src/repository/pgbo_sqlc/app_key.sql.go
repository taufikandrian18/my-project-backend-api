// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.13.0
// source: app_key.sql

package sqlc

import (
	"context"
)

const getAppKeyByName = `-- name: GetAppKeyByName :one
SELECT
    ak.id,
    ak.name,
    ak.key
FROM app_key ak
WHERE
        ak.name = $1
`

func (q *Queries) GetAppKeyByName(ctx context.Context, name string) (AppKey, error) {
	row := q.db.QueryRowContext(ctx, getAppKeyByName, name)
	var i AppKey
	err := row.Scan(&i.ID, &i.Name, &i.Key)
	return i, err
}
