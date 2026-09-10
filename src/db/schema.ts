import { pgTable, text, integer, timestamp, jsonb, serial } from 'drizzle-orm/pg-core';
export const boardTasks = pgTable('veritas_demo_tasks', {
 id:text('id').primaryKey(), title:text('title').notNull(), description:text('description').notNull(),
 status:text('status').notNull().default('BACKLOG'), priority:text('priority').notNull().default('Medium'),
 agent:text('agent').notNull().default('Unassigned'), category:text('category').notNull().default('Platform'),
 criteria:jsonb('criteria').$type<string[]>().notNull().default([]), revision:integer('revision').notNull().default(1),
 createdAt:timestamp('created_at',{withTimezone:true}).notNull().defaultNow(),
});
export const boardEvents = pgTable('veritas_demo_events', {
 id:serial('id').primaryKey(), taskId:text('task_id').notNull(), action:text('action').notNull(),
 detail:text('detail').notNull(), revision:integer('revision').notNull(), operationId:text('operation_id').unique().notNull(),
 requestHash:text('request_hash'), snapshot:jsonb('snapshot').$type<Record<string,unknown>>(),
 createdAt:timestamp('created_at',{withTimezone:true}).notNull().defaultNow(),
});
